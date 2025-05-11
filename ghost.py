import hmac
import hashlib
import json
from typing import Dict, Optional, Union

def parse_ghost_signature(signature_header: str) -> Dict[str, Union[bool, Optional[str]]]:
    """Parse the Ghost webhook signature header.
    
    Args:
        signature_header: The signature header from Ghost webhook
        
    Returns:
        Dictionary with success status and signature data
    """
    if not signature_header:
        return {'success': False, 'signature': None}
    
    try:
        return {'success': True, 'signature': signature_header}
    except Exception:
        return {'success': False, 'signature': None}

def create_ghost_signature(payload: Dict, secret: str) -> str:
    """Create a signature for Ghost webhook payload.
    
    Args:
        payload: The webhook payload
        secret: The webhook secret
        
    Returns:
        The computed signature
    """
    payload_string = json.dumps(payload)
    return hmac.new(secret.encode('utf-8'), payload_string.encode('utf-8'), hashlib.sha256).hexdigest()

def ghost_verify_signature(signature_header: Optional[str], payload: Optional[Dict], secret: str) -> bool:
    """Verify that the payload was sent from Ghost by validating signature.
    
    Args:
        signature_header: Header received from Ghost
        payload: The webhook payload
        secret: The webhook secret
        
    Returns:
        True if signature is valid, False otherwise
    """
    if not signature_header or not payload:
        return False
    
    parse_result = parse_ghost_signature(signature_header)
    if not parse_result['success']:
        return False
    
    incoming_signature = parse_result['signature']
    computed_signature = create_ghost_signature(payload, secret)
    
    try:
        return hmac.compare_digest(computed_signature, incoming_signature)
    except Exception:
        return False
