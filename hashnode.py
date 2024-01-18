import hmac
import hashlib
import json
import time
from typing import Dict, Tuple, Union, Optional

MILLISECONDS_PER_SECOND = 1000
SIGNATURE_VERSION = '1'

def parse_signature_header(header: str) -> Dict[str, Union[bool, Optional[Dict[str, Union[int, str]]]]]:
    parts = header.split(',')
    timestamp_part = next((part for part in parts if part.startswith('t=')), None)
    signature_part = next((part for part in parts if part.startswith(f'v{SIGNATURE_VERSION}=')), None)

    timestamp = None
    signature = None
    if timestamp_part:
        timestamp = int(timestamp_part.split('=')[1])
    if signature_part:
        signature = signature_part.split('=')[1]

    if not timestamp or not signature:
        return {'success': False, 'data': None}

    return {'success': True, 'data': {'timestamp': timestamp, 'signature': signature}}

def create_signature(timestamp: int, payload: Optional[Dict], secret: str) -> str:
    signed_payload_string = f'{timestamp}.{json.dumps(payload) if payload else ""}'
    return hmac.new(secret.encode(), signed_payload_string.encode(), hashlib.sha256).hexdigest()

def hn_validate_signature(incoming_signature_header: Optional[str], payload: Optional[Dict], secret: str, valid_for_seconds: int = 30) -> Dict[str, Union[bool, str]]:
    if not incoming_signature_header:
        return {'isValid': False, 'reason': 'Missing signature'}

    parse_result = parse_signature_header(incoming_signature_header)
    if not parse_result['success']:
        return {'isValid': False, 'reason': 'Invalid signature header'}

    parsed_data = parse_result['data']
    incoming_signature_timestamp = parsed_data['timestamp']
    incoming_signature = parsed_data['signature']

    signature = create_signature(incoming_signature_timestamp, payload, secret)
    is_signature_valid = compare_signatures(signature, incoming_signature)
    if not is_signature_valid:
        return {'isValid': False, 'reason': 'Invalid signature'}

    if valid_for_seconds != 0:
        difference_in_seconds = abs((time.time() * 1000 - incoming_signature_timestamp) / MILLISECONDS_PER_SECOND)
        if difference_in_seconds > valid_for_seconds:
            return {'isValid': False, 'reason': 'Invalid timestamp'}

    return {'isValid': True}

def compare_signatures(signature_a: str, signature_b: str) -> bool:
    try:
        return hmac.compare_digest(signature_a, signature_b)
    except Exception as e:
        return False
