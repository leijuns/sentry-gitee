"""
sentry_gitee.plugin
~~~~~~~~~~~~~~~~~~~~

:copyright: (c) 2012 by the Sentry Team, see AUTHORS for more details.
:license: BSD, see LICENSE for more details.
"""
from urllib import quote

from django import forms
from django.utils.translation import ugettext_lazy as _
from sentry.http import build_session
from sentry.plugins.bases.issue import IssuePlugin
from requests.exceptions import HTTPError

import sentry_gitee


class GiteeOptionsForm(forms.Form):
    gitee_owner = forms.CharField(
        label=_('Gitee namespace'),
        widget=forms.TextInput(attrs={'placeholder': 'e.g. xxxx'}),
        help_text=_('Enter your namespace'),
        required=True,
    )

    gitee_repo = forms.CharField(
        label=_('Repository Name'),
        widget=forms.TextInput(attrs={'placeholder': 'e.g. reponame'}),
        help_text=_('Enter your repository name'),
        required=True)

    gitee_token = forms.CharField(
        label=_('Gitee Private Token'),
        widget=forms.TextInput(attrs={'placeholder': 'e.g. g5DWFtLzaztgYFrqhVfE'}),
        help_text=_('Enter your Gitee API token'),
        required=True)

    gitee_labels = forms.CharField(
        label=_('Issue Labels'),
        widget=forms.TextInput(attrs={'placeholder': 'e.g. high, bug'}),
        help_text=_('Enter the labels you want to auto assign to new issues.'),
        required=False)

    def clean(self):
        owner = self.cleaned_data['gitee_owner']
        token = self.cleaned_data['gitee_token']
        repo = self.cleaned_data['gitee_repo']

        session = build_session()

        try:
            session.head(
                url='https://gitee.com/api/v5/repos/%s/%s' % (owner, repo),
                data={
                    'access_token': token,
                },
                allow_redirects=False,
            ).raise_for_status()
        except HTTPError as e:
            # Handle Unauthorized special
            if e.response.status_code == 401:
                raise forms.ValidationError(_('Unauthorized: Invalid Private Token: %s') % (e,))
            if e.response.status_code == 404:
                raise forms.ValidationError(_('Invalid Repository Name'))
            raise forms.ValidationError(_('Error Communicating with Gitee: %s') % (e,))
        except Exception as e:
            raise forms.ValidationError(_('Error Communicating with Gitee: %s') % (e,))

        return self.cleaned_data


class GiteePlugin(IssuePlugin):
    author = 'lei2jun'
    author_url = 'https://gitee.com/lei2jun/sentry-gitee'
    version = sentry_gitee.VERSION
    description = "Integrate Gitee issues by linking a repository to a project"
    resource_links = [
        ('Bug Tracker', 'https://gitee.com/lei2jun/sentry-gitee/issues'),
        ('Source', 'https://gitee.com/lei2jun/sentry-gitee'),
    ]

    slug = 'gitee'
    title = _('Gitee')
    conf_title = title
    conf_key = 'gitee'
    project_conf_form = GiteeOptionsForm

    def is_configured(self, request, project, **kwargs):
        return bool(self.get_option('gitee_repo', project))

    def get_new_issue_title(self, **kwargs):
        return 'Create Gitee Issue'

    def create_issue(self, request, group, form_data, **kwargs):
        owner = self.get_option('gitee_owner', group.project)
        token = self.get_option('gitee_token', group.project)
        repo = self.get_option('gitee_repo', group.project)
        labels = self.get_option('gitee_labels', group.project)

        session = build_session()

        try:
            response = session.post(
                url='https://gitee.com/api/v5/repos/%s/issues' % (owner),
                data={
                    'access_token': token,
                    'repo': repo,
                    'title': form_data['title'],
                    'body': form_data['description'],
                    'labels': labels,
                },
                allow_redirects=False,
            )
            response.raise_for_status()

            return response.json()['id']
        except HTTPError as e:
            # Handle Unauthorized special
            if e.response.status_code == 401:
                raise forms.ValidationError(_('Unauthorized: Invalid Private Token: %s') % (e,))

            self.logger.error('Failed to create Gitee issue', exc_info=True)
            raise forms.ValidationError(_('Error Communicating with Gitee: %s') % (e,))
        except Exception as e:
            self.logger.error('Failed to create Gitee issue', exc_info=True)
            raise forms.ValidationError(_('Error Communicating with Gitee: %s') % (e,))

    def get_issue_label(self, group, issue_id, **kwargs):
        return 'ISSUE-%s' % issue_id

    def get_issue_url(self, group, issue_id, **kwargs):
        owner = self.get_option('gitee_owner', group.project)
        repo = self.get_option('gitee_repo', group.project)

        return 'https://gitee.com/%s/%s/issues/%s' % (owner, repo, issue_id)
