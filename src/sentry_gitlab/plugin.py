"""
sentry_gitlab.plugin
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

import sentry_gitlab


class GitLabOptionsForm(forms.Form):
    gitlab_url = forms.CharField(
        label=_('GitLab URL'),
        widget=forms.TextInput(attrs={'placeholder': 'e.g. https://gitlab.example.com'}),
        help_text=_('Enter the URL for your GitLab server'),
        required=True,
        initial='https://gitlab.com',
    )

    gitlab_token = forms.CharField(
        label=_('GitLab Private Token'),
        widget=forms.TextInput(attrs={'placeholder': 'e.g. g5DWFtLzaztgYFrqhVfE'}),
        help_text=_('Enter your GitLab API token'),
        required=True)

    gitlab_repo = forms.CharField(
        label=_('Repository Name'),
        widget=forms.TextInput(attrs={'placeholder': 'e.g. namespace/repo'}),
        help_text=_('Enter your repository name, including namespace.'),
        required=True)

    gitlab_labels = forms.CharField(
        label=_('Issue Labels'),
        widget=forms.TextInput(attrs={'placeholder': 'e.g. high, bug'}),
        help_text=_('Enter the labels you want to auto assign to new issues.'),
        required=False)

    def clean(self):
        url = self.cleaned_data['gitlab_url'].rstrip('/')
        token = self.cleaned_data['gitlab_token']
        repo = self.cleaned_data['gitlab_repo']
        repo_url = quote(repo, safe='')

        headers = {'Private-Token': token}
        session = build_session()

        try:
            session.head(
                url='%s/api/v3/projects/%s' % (url, repo_url),
                headers=headers,
                allow_redirects=False,
            ).raise_for_status()
        except HTTPError as e:
            # Handle Unauthorized special
            if e.response.status_code == 401:
                raise forms.ValidationError(_('Unauthorized: Invalid Private Token: %s') % (e,))
            if e.response.status_code == 404:
                raise forms.ValidationError(_('Invalid Repository Name'))
            raise forms.ValidationError(_('Error Communicating with GitLab: %s') % (e,))
        except Exception as e:
            raise forms.ValidationError(_('Error Communicating with GitLab: %s') % (e,))

        return self.cleaned_data


class GitLabPlugin(IssuePlugin):
    author = 'Sentry Team'
    author_url = 'https://github.com/getsentry/sentry-gitlab'
    version = sentry_gitlab.VERSION
    description = "Integrate GitLab issues by linking a repository to a project"
    resource_links = [
        ('Bug Tracker', 'https://github.com/getsentry/sentry-gitlab/issues'),
        ('Source', 'https://github.com/getsentry/sentry-gitlab'),
    ]

    slug = 'gitlab'
    title = _('GitLab')
    conf_title = title
    conf_key = 'gitlab'
    project_conf_form = GitLabOptionsForm

    def is_configured(self, request, project, **kwargs):
        return bool(self.get_option('gitlab_repo', project))

    def get_new_issue_title(self, **kwargs):
        return 'Create GitLab Issue'

    def create_issue(self, request, group, form_data, **kwargs):
        url = self.get_option('gitlab_url', group.project).rstrip('/')
        token = self.get_option('gitlab_token', group.project)
        repo = self.get_option('gitlab_repo', group.project)
        labels = self.get_option('gitlab_labels', group.project)
        repo_url = quote(repo, safe='')

        headers = {'Private-Token': token}
        session = build_session()

        try:
            response = session.post(
                url='%s/api/v3/projects/%s/issues' % (url, repo_url),
                headers=headers,
                data={
                    'title': form_data['title'],
                    'description': form_data['description'],
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

            self.logger.error('Failed to create GitLab issue', exc_info=True)
            raise forms.ValidationError(_('Error Communicating with GitLab: %s') % (e,))
        except Exception as e:
            self.logger.error('Failed to create GitLab issue', exc_info=True)
            raise forms.ValidationError(_('Error Communicating with GitLab: %s') % (e,))

    def get_issue_label(self, group, issue_id, **kwargs):
        return 'GL-%s' % issue_id

    def get_issue_url(self, group, issue_id, **kwargs):
        url = self.get_option('gitlab_url', group.project).rstrip('/')
        repo = self.get_option('gitlab_repo', group.project)

        return '%s/%s/issues/%s' % (url, repo, issue_id)
