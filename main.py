from flask import Flask, request, jsonify
import requests
from hashnode import hn_validate_signature
from github import gh_verify_signature
from ghost import ghost_verify_signature
import os
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)

INDEX_TEMPLATE = """
<!DOCTYPE html>
<head>
  <title>Bang! Bang!</title>
</head>
<body>
    <h1>Bang! Bang!</h1>
</body>
"""

@app.route('/', methods=['GET', 'POST'])
def trigger_github_workflow():
    if request.method != "POST":
        return INDEX_TEMPLATE
    
    request_json = request.get_json(silent=True)
    hn_signature = request.headers.get('x-hashnode-signature', None)
    gh_signature = request.headers.get('x-hub-signature-256', None)
    ghost_signature = request.headers.get('x-ghost-signature', None)
    actual_secret = os.environ.get('HASHNODE_WEBHOOK_SECRET')
    ghost_secret = os.environ.get('GHOST_WEBHOOK_SECRET')
    hn_validated, gh_validated, ghost_validated = False, False, False

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

    if ghost_signature:
        try:
            ghost_validated = ghost_verify_signature(ghost_signature, request_json, ghost_secret)
        except:
            pass

    if hn_validated or gh_validated or ghost_validated: 
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

        return jsonify({"message": "Whoosh we go!"})
    else:
        return jsonify({"message": "Your mischief has been logged."})

if __name__ == '__main__':
    app.run(debug=True)