# trigger_workflow.py
import requests
import os
from dotenv import load_dotenv

load_dotenv()

def trigger_github_workflow():
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

    response = requests.post(url, headers=headers, json=payload)
    return response.status_code, response.text

if __name__ == '__main__':
    status_code, text = trigger_github_workflow()
    print(f'Status Code: {status_code}\nResponse: {text}')
