"""
IDOR (Insecure Direct Object Reference) Detection Module.
"""
import re
import logging
from typing import Dict, List, Optional
from ..core.data_models import AtomicFinding, VulnerabilityType, SeverityLevel

logger = logging.getLogger(__name__)


class IDORDetector:
    """Detects potential IDOR vulnerabilities."""

    # Common patterns for user IDs and object references
    PATTERNS = {
        'user_id': r'user(?:_)?id|uid|userid|u_id|user_no|account_id',
        'object_id': r'(?:id|object_id|item_id|doc_id|record_id|resource_id)=(\d+)',
        'path_id': r'/(?:api|v\d+)?/(?:users|accounts|profiles|objects|items)/(\d+)',
        'sequential_id': r'[?&]id=(\d+)',
    }

    @staticmethod
    def detect_from_url(
        url: str,
        source_user: str = "anonymous",
        target_privilege: int = 50
    ) -> Optional[AtomicFinding]:
        """
        Detect potential IDOR from URL patterns.
        
        Args:
            url: URL to analyze
            source_user: User/role that can access the URL
            target_privilege: Privilege level of accessed data
            
        Returns:
            AtomicFinding if IDOR is detected, None otherwise
        """
        # Extract potential IDs from URL
        match = re.search(IDORDetector.PATTERNS['object_id'], url)
        if not match:
            match = re.search(IDORDetector.PATTERNS['path_id'], url)
        if not match:
            match = re.search(IDORDetector.PATTERNS['sequential_id'], url)
        
        if match:
            obj_id = match.group(1)
            
            # Check for sequential/enumerable IDs
            if re.match(r'^\d{1,4}$', obj_id):
                finding = AtomicFinding(
                    id=f"idor_{source_user}_{obj_id}",
                    finding_type=VulnerabilityType.IDOR,
                    severity=SeverityLevel.HIGH,
                    source_node=source_user,
                    target_node=f"object_{obj_id}",
                    description=f"Potential IDOR: User {source_user} can enumerate objects via sequential IDs in {url}",
                    confidence=0.8,
                    metadata={'url': url, 'object_id': obj_id}
                )
                logger.info(f"Detected potential IDOR: {url}")
                return finding
        
        return None

    @staticmethod
    def detect_from_api_response(
        response_data: Dict,
        endpoint: str,
        accessed_by: str,
        expected_user: str = None
    ) -> Optional[AtomicFinding]:
        """
        Detect IDOR from API response analysis.
        
        Args:
            response_data: API response data
            endpoint: Endpoint that was accessed
            accessed_by: User/role that accessed the endpoint
            expected_user: Expected user if authorization is working
            
        Returns:
            AtomicFinding if IDOR is detected, None otherwise
        """
        # Check if we got data for a different user than expected
        if expected_user and 'user_id' in response_data:
            if response_data['user_id'] != expected_user:
                finding = AtomicFinding(
                    id=f"idor_response_{accessed_by}_{expected_user}",
                    finding_type=VulnerabilityType.IDOR,
                    severity=SeverityLevel.CRITICAL,
                    source_node=accessed_by,
                    target_node=f"user_{response_data['user_id']}",
                    description=f"IDOR confirmed: User {accessed_by} accessed user {response_data['user_id']}'s data via {endpoint}",
                    confidence=1.0,
                    metadata={
                        'endpoint': endpoint,
                        'accessed_user': response_data['user_id'],
                        'accessed_by': accessed_by
                    }
                )
                logger.warning(f"Confirmed IDOR: {endpoint}")
                return finding
        
        return None

    @staticmethod
    def bulk_analyze(urls: List[str], source_user: str = "anonymous") -> List[AtomicFinding]:
        """
        Analyze multiple URLs for IDOR vulnerabilities.
        
        Args:
            urls: List of URLs to analyze
            source_user: User/role performing the analysis
            
        Returns:
            List of detected IDOR findings
        """
        findings = []
        for url in urls:
            finding = IDORDetector.detect_from_url(url, source_user)
            if finding:
                findings.append(finding)
        
        logger.info(f"Bulk analysis found {len(findings)} potential IDOR vulnerabilities")
        return findings
