#!/usr/bin/env python

from __future__ import print_function
import sys
import base64
import time

import httplib2
import json
import webapp2
import jwt
from apiclient import discovery

from jwt.contrib.algorithms.pycrypto import RSAAlgorithm
jwt.register_algorithm('RS256', RSAAlgorithm(RSAAlgorithm.SHA256))

from config import *

##
## there's no real recourse on errors, so we won't be
## handling many
##

# github is slow sometimes, and GAE's default timeouts are agressive
from google.appengine.api import urlfetch
urlfetch.set_default_fetch_deadline(10)

class WebHook(webapp2.RequestHandler):
    def post(self):

        result = json.loads(self.request.body)
        action = result.get('action')
        # installation is the ID of the entity calling out to us,
        # needed to get an auth token later
        if result.get('installation', None):
            installation_id = result.get('installation').get('id')
        else:
            installation_id = None

        # check the PR on these events
        # synchronize covers new commits
        if action == 'opened' or action == 'synchronize' or action == 'edited' or action == 'reopened':
            print('Checking PR status. Action is "{}"'.format(action))
            token = get_token(installation_id)
            if not token:
                token = github_api_token
            check_pr(result.get('pull_request'), token)
        else:
            print('No changes, NOT checking PR status. Action was "{}"'.format(action))


# authenticate to github with our private key and get a token
# to authenticate to the installation
def get_token(id):
    data = {
        'iat': int(time.time()),
        'exp': int(time.time()) + 60*10,
        'iss': app_id
        }

    web_token = jwt.encode(data, base64.b64decode(github_key_base64), algorithm='RS256')

    headers = {
        'Authorization': 'Bearer {}'.format(web_token),
        'Accept': 'application/vnd.github.machine-man-preview+json'
        }

    url = 'https://api.github.com/installations/{}/access_tokens'.format(id)

    http = httplib2.Http()
    response, content = http.request(url, 'POST', headers=headers)

    return json.loads(content).get('token', None)


# fetch an array of github IDs from the Google Sheet
def get_signers():
    sheet_url = 'https://sheets.googleapis.com/$discovery/rest?version=v4'
    results = []

    http = httplib2.Http()
    service = discovery.build('sheets', 'v4', http=http,
       discoveryServiceUrl=sheet_url, developerKey=google_api_key)

    result = service.spreadsheets().values().get(
        spreadsheetId=sheet_id, range=sheet_query).execute()

    for r in result.get('values', []):
        if r[sheet_true_column] == 'TRUE' and r[sheet_user_column] != '': 
            results.append(r[sheet_user_column])

    return results


# check the PR for commits with unsigned authors
def check_pr(pr, token):
    signed = True

    status_url = pr.get('head').get('repo').get('statuses_url')
    issue_url = pr.get('issue_url')
    comments_url = pr.get('comments_url')

    commits = github_get(pr.get('commits_url'), token)

    authorized_users = get_signers()

    # check every commit in the PR
    for c in commits:
        user = c.get('author').get('login')
        sha = c.get('sha')
        status_url_sha = str(status_url).format(sha=sha)

        user_email = c.get('commit').get('author').get('email')
        user_name = c.get('commit').get('author').get('name')
        # TODO match company domains
        print(u'Checking {} "{}"'.format(user_email, user_name))

        if user in authorized_users:
            print('Author "{}" HAS signed the CLA for commit {}'.format(user, sha))
            github_post(status_url_sha, token, { 'state': 'success', 'context': bot_context })
        else:
            print('Author "{}" has NOT signed the CLA for commit {}'.format(user, sha ))
            github_post(status_url_sha, token, { 'state': 'error', 'context': bot_context })
            signed = False

    # check if the bot has previously labeled or commented
    bot_labels = [ i for i in github_get(issue_url + '/labels', token) if i['name'] == bot_label ]
    bot_comments = [ i for i in github_get(issue_url + '/comments', token) if i['body'] == bot_message ]

    if not signed:
        print('CLA not signed for at least one commit')
        print('Deleting any existing labels')
        github_delete(issue_url + '/labels/' + bot_label, token)
        if bot_comments:
            print('PR already has a bot comment, skipping')
        else:
            print('Commenting on PR')
            github_post(comments_url, token, { 'body': bot_message })

    else:
        print('CLA has been signed for all commits, adding label to PR')
        github_post(issue_url + '/labels', token, [ bot_label ])
        for c in bot_comments:
            print('Removing bot comments')
            github_delete(c.get('url'), token)


def github_post(url, token, data):
    headers = {
        'Authorization': 'token {}'.format(token),
        'Content-Type': 'application/json'
        }

    print('POST {} ({})'.format(url, data))
    http = httplib2.Http()
    response, content = http.request(url, 'POST', headers=headers, body=json.dumps(data))
    return response

def github_get(url, token):
    headers = {
        'Authorization': 'token {}'.format(token),
        'Content-Type': 'application/json'
        }

    print('GET {}'.format(url))
    http = httplib2.Http()
    response, content = http.request(url, 'GET', headers=headers)
    return json.loads(content)

def github_delete(url, token):
    headers = {
        'Authorization': 'token {}'.format(token),
        'Content-Type': 'application/json'
        }

    print('DELETE {}'.format(url))
    http = httplib2.Http()
    response, content = http.request(url, 'DELETE', headers=headers)
    return response


app = webapp2.WSGIApplication([('/', WebHook)], debug=True)

if __name__ == '__main__':
    sys.exit(0)

