from flask import Flask, request, jsonify
import requests
from hashnode import hn_validate_signature
from github import gh_verify_signature
from ghost import ghost_verify_signature
import os
from dotenv import load_dotenv
import logging
import json
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

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
        logger.info("Returning index template for GET request")
        return INDEX_TEMPLATE
    
    # request_data = request.data
    # request_json = request.json
    request_data = request.get_data().decode()
    
    hn_signature = request.headers.get('x-hashnode-signature', None)
    gh_signature = request.headers.get('x-hub-signature-256', None)
    ghost_signature = request.headers.get('x-ghost-signature', None)
    
    logger.info(f"Headers received - Hashnode: {bool(hn_signature)}, GitHub: {bool(gh_signature)}, Ghost: {bool(ghost_signature)}")
    
    actual_secret = os.environ.get('HASHNODE_WEBHOOK_SECRET', None)
    ghost_secret = os.environ.get('GHOST_WEBHOOK_SECRET', None)
    hn_validated, gh_validated, ghost_validated = False, False, False

    if hn_signature:
        try:
            logger.info("Attempting to validate Hashnode signature")
            validation_result = hn_validate_signature(hn_signature, request_data, actual_secret)
            hn_validated = validation_result.get('isValid', False)
            logger.info(f"Hashnode validation result: {validation_result}")
        except Exception as e:
            logger.error(f"HN Verification error: {str(e)}")
            pass

    if gh_signature:
        try:
            logger.info("Attempting to validate GitHub signature")
            gh_validated = gh_verify_signature(request.data, actual_secret, gh_signature)
            logger.info(f"GitHub validation result: {gh_validated}")
        except Exception as e:
            logger.error(f"GitHub Verification error: {str(e)}")
            pass

    if ghost_signature:
        try:
            logger.info("Attempting to validate Ghost signature")
            ghost_validated = ghost_verify_signature(ghost_signature, request_data, ghost_secret)
            logger.info(f"Ghost validation result: {ghost_validated}")
        except Exception as e:
            logger.error(f"Ghost Verification error: {str(e)}")
            pass

    logger.info(f"Validation results - Hashnode: {hn_validated}, GitHub: {gh_validated}, Ghost: {ghost_validated}")

    if hn_validated or gh_validated or ghost_validated: 
        token = os.environ.get('GH_TOKEN')
        owner = os.environ.get('GH_USERNAME')
        repo = os.environ.get('GH_REPO')
        workflow_id = os.environ.get('GH_WORKFLOW_FILENAME')
        branch = os.environ.get('GH_BRANCH')

        url = f'https://api.github.com/repos/{owner}/{repo}/actions/workflows/{workflow_id}/dispatches'
        logger.info(f"Triggering GitHub workflow at: {url} with branch: {branch}")

        headers = {
            'Authorization': f'token {token}',
            'Accept': 'application/vnd.github.v3+json'
        }

        payload = {
            'ref': branch
        }

        try:
            response = requests.post(url, headers=headers, json=payload)
            logger.info(f"GitHub API response: {response.status_code}")
            if response.status_code >= 400:
                logger.error(f"GitHub API error: {response.text}")
        except Exception as e:
            logger.error(f"Error triggering GitHub workflow: {str(e)}")

        logger.info("Webhook processed successfully")
        return jsonify({"message": "Whoosh we go!"})
    else:
        logger.warning("Unauthorized webhook attempt detected")
        return jsonify({"message": "Your mischief has been logged."})

if __name__ == '__main__':
    port = os.environ.get('PORT', 8080)
    logger.info(f"Starting application on port {port}")
    app.run(debug=True, port=port)