import functions_framework
import requests
from hashnode import hn_validate_signature
from github import gh_verify_signature
import os
from dotenv import load_dotenv

load_dotenv()


INDEX_TEMPLATE = """
<!DOCTYPE html>
<head>
  <title>Bang! Bang!</title>
</head>
<body>
I know nothing. I am Jon Snow.
</body>
"""


@functions_framework.http
def trigger_github_workflow(request):

    if request.method != "POST":
        return INDEX_TEMPLATE
    else:
        request_json = request.get_json(silent=True)
        hn_signature = request.headers.get('x-hashnode-signature', None)
        gh_signature = request.headers.get('x-hub-signature-256', None)

        actual_secret = os.environ.get('HASHNODE_WEBHOOK_SECRET')

        hn_validated, gh_validated = False, False


        if hn_signature:
            try:
                hn_validated = hn_validate_signature(hn_signature, request_json, actual_secret)
            except:
                print("HN Verification error")
                pass

        if gh_signature:
            try:
                gh_validated = gh_verify_signature(request.data, actual_secret, gh_signature)
            except:
                pass

        if hn_validated or gh_validated: 
            token = os.environ.get('GH_TOKEN')
            owner = os.environ.get('GH_USERNAME')
            repo = os.environ.get('GH_REPO')
            workflow_id = os.environ.get('GH_WORKFLOW_FILENAME')

            url = f'https://api.github.com/repos/{owner}/{repo}/actions/workflows/{workflow_id}/dispatches'

            headers = {
                'Authorization': f'token {token}',
                'Accept': 'application/vnd.github.v3+json'
            }

            payload = {
                'ref': os.environ.get('GH_BRANCH')
            }

            requests.post(url, headers=headers, json=payload)

            return {"message": "Whoosh we go!"}
        else:

            return {"message": "Your mischief has been logged."}