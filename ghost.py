import hmac
import hashlib
import json
from typing import Dict, Optional, Union, Tuple, Any
import time
import logging

logger = logging.getLogger(__name__)

def parse_signature_header(header: str) -> Tuple[Optional[str], Optional[int]]:
    """Parse the Ghost signature header to extract signature and timestamp.
    
    Args:
        header: The signature header from Ghost
        
    Returns:
        Tuple containing (signature, timestamp) or (None, None) if parsing fails
    """
    try:
        parts = [part.strip() for part in header.split(",")]
        sig = None
        timestamp = None
        for part in parts:
            if part.startswith("sha256="):
                sig = part[len("sha256="):]
            elif part.startswith("t="):
                timestamp = int(part[len("t="):])
        return sig, timestamp
    except Exception:
        return None, None


def ghost_verify_signature(signature_header: str, payload, secret: str) -> bool:
    """Verify that the payload was sent from Ghost by validating signature.
    
    Args:
        signature_header: Header received from Ghost
        payload: The webhook payload
        secret: The webhook secret
        
    Returns:
        True if signature is valid, False otherwise
    """
    logger.info("Verifying Ghost signature")
    if not signature_header or not payload:
        return False
    
    logger.info(f"Secret: {secret}")
    logger.info(f"Payload Length: {len(payload)}")
    
    # Parse the signature header to get signature and timestamp
    received_sig, timestamp = parse_signature_header(signature_header)
    logger.info(f"Received sig: {received_sig}, Timestamp: {timestamp}")
    if not received_sig or not timestamp:
        return False
    
    # Check timestamp freshness (5 minutes drift allowed)
    now = int(time.time() * 1000)
    if abs(now - timestamp) > 300000 * 1000:  # 300 seconds = 5 minutes
        return False
    
    logger.info("Computing signature")
    # Compute signature
    computed_sig = hmac.new(
        secret.encode(), f"{payload}{timestamp}".encode(), hashlib.sha256
    ).hexdigest()
    
    logger.info(f"Computed sig: {computed_sig}")
    logger.info(f"Received sig: {received_sig}")

    try:
        return hmac.compare_digest(computed_sig, received_sig)
    except Exception:
        return False
