"""
Sensitive Data Exposure Detection Module.
Detects and classifies sensitive information exposure vulnerabilities.
"""
import logging
import re
from typing import Dict, List, Optional, Tuple
from ..core.data_models import AtomicFinding, VulnerabilityType, SeverityLevel

logger = logging.getLogger(__name__)


class SensitiveDataExposureDetector:
    """Detects sensitive data exposure vulnerabilities."""

    # Patterns for detecting sensitive data
    SENSITIVE_PATTERNS = {
        'email': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
        'phone': r'\+?1?\d{9,15}',
        'ssn': r'\d{3}-\d{2}-\d{4}',
        'credit_card': r'\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}',
        'api_key': r'(?:api[_-]?key|apikey|access[_-]?token)[=:\s]+([a-zA-Z0-9]{20,})',
        'private_key': r'-----BEGIN [A-Z ]+ PRIVATE KEY-----',
        'password': r'(?:password|passwd|pwd)[=:\s]+([^\s&\n]+)',
        'jwt': r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*',
        'database_url': r'(?:mysql|postgres|mongodb)://[^\s]+',
    }

    @staticmethod
    def detect_in_response(
        response_data: str,
        endpoint: str,
        accessed_by: str,
        is_public: bool = False
    ) -> List[AtomicFinding]:
        """
        Detect sensitive data exposure in response body.
        
        Args:
            response_data: Response body/data as string
            endpoint: Endpoint that returned the data
            accessed_by: User/role that accessed the endpoint
            is_public: Whether endpoint is publicly accessible
            
        Returns:
            List of AtomicFindings for each type of sensitive data found
        """
        findings = []
        
        for data_type, pattern in SensitiveDataExposureDetector.SENSITIVE_PATTERNS.items():
            matches = re.findall(pattern, response_data, re.IGNORECASE)
            
            if matches:
                # Determine severity
                if is_public:
                    severity = SeverityLevel.CRITICAL
                elif data_type in ['private_key', 'api_key', 'database_url']:
                    severity = SeverityLevel.CRITICAL
                elif data_type in ['credit_card', 'ssn']:
                    severity = SeverityLevel.CRITICAL
                elif data_type in ['email', 'password']:
                    severity = SeverityLevel.HIGH
                else:
                    severity = SeverityLevel.MEDIUM
                
                finding = AtomicFinding(
                    id=f"sensitive_data_{data_type}_{endpoint.replace('/', '_')}",
                    finding_type=VulnerabilityType.SENSITIVE_DATA_EXPOSURE,
                    severity=severity,
                    source_node=accessed_by,
                    target_node=f"sensitive_data_{data_type}",
                    description=f"{data_type.upper()} exposure: {len(matches)} instance(s) found in {endpoint} response",
                    confidence=min(len(matches) * 0.2, 1.0),
                    metadata={
                        'endpoint': endpoint,
                        'data_type': data_type,
                        'num_matches': len(matches),
                        'is_public': is_public,
                        'sample': matches[0] if matches else None
                    }
                )
                findings.append(finding)
                logger.warning(f"Detected {data_type} exposure: {endpoint}")
        
        return findings

    @staticmethod
    def detect_in_logs(
        log_content: str,
        log_name: str = "application.log"
    ) -> List[AtomicFinding]:
        """
        Detect sensitive data in application logs.
        
        Args:
            log_content: Log file content
            log_name: Name of the log file
            
        Returns:
            List of AtomicFindings for sensitive data in logs
        """
        findings = []
        
        for data_type, pattern in SensitiveDataExposureDetector.SENSITIVE_PATTERNS.items():
            matches = re.findall(pattern, log_content, re.IGNORECASE)
            
            if matches:
                finding = AtomicFinding(
                    id=f"log_exposure_{data_type}_{log_name}",
                    finding_type=VulnerabilityType.INFORMATION_DISCLOSURE,
                    severity=SeverityLevel.HIGH,
                    source_node="system",
                    target_node=f"log_{log_name}",
                    description=f"{data_type.upper()} exposed in logs: {log_name} contains {len(matches)} instance(s)",
                    confidence=0.95,
                    metadata={
                        'log_file': log_name,
                        'data_type': data_type,
                        'num_matches': len(matches)
                    }
                )
                findings.append(finding)
                logger.warning(f"Detected {data_type} in logs: {log_name}")
        
        return findings

    @staticmethod
    def detect_debug_info_exposure(
        response_data: str,
        endpoint: str,
        indicators: List[str] = None
    ) -> Optional[AtomicFinding]:
        """
        Detect debug information exposure (stack traces, SQL errors, etc).
        
        Args:
            response_data: Response body
            endpoint: Endpoint URL
            indicators: List of debug indicators to search for
            
        Returns:
            AtomicFinding if debug info is detected
        """
        if not indicators:
            indicators = [
                'stack trace', 'stacktrace', 'traceback',
                'sql error', 'sql exception', 'syntax error',
                'warning:', 'fatal error', 'deprecated',
                'debug', 'at line', 'at offset'
            ]
        
        found_indicators = [ind for ind in indicators if ind.lower() in response_data.lower()]
        
        if found_indicators:
            finding = AtomicFinding(
                id=f"debug_exposure_{endpoint.replace('/', '_')}",
                finding_type=VulnerabilityType.INFORMATION_DISCLOSURE,
                severity=SeverityLevel.MEDIUM,
                source_node="application",
                target_node=f"endpoint_{endpoint.replace('/', '_')}",
                description=f"Debug information exposed: {endpoint} returns debug details",
                confidence=0.9,
                metadata={
                    'endpoint': endpoint,
                    'indicators_found': found_indicators
                }
            )
            logger.warning(f"Detected debug info exposure: {endpoint}")
            return finding
        
        return None

    @staticmethod
    def detect_in_metadata(
        metadata: Dict,
        source: str = "http_headers"
    ) -> List[AtomicFinding]:
        """
        Detect sensitive information in metadata (headers, cookies, etc).
        
        Args:
            metadata: Metadata dictionary
            source: Source of metadata (e.g., 'http_headers', 'cookies')
            
        Returns:
            List of AtomicFindings
        """
        findings = []
        
        sensitive_metadata_keys = [
            'x-powered-by', 'server', 'x-aspnet-version',
            'x-runtime-version', 'set-cookie', 'authorization',
            'x-debug', 'x-debug-token', 'x-internal-id'
        ]
        
        for key, value in metadata.items():
            key_lower = key.lower()
            
            # Check for sensitive keys
            if key_lower in sensitive_metadata_keys:
                finding = AtomicFinding(
                    id=f"metadata_exposure_{source}_{key}",
                    finding_type=VulnerabilityType.INFORMATION_DISCLOSURE,
                    severity=SeverityLevel.MEDIUM,
                    source_node="server",
                    target_node=f"client",
                    description=f"Sensitive metadata exposed: {key}={value}",
                    confidence=0.9,
                    metadata={
                        'source': source,
                        'key': key,
                        'value': str(value)[:50]  # Truncate long values
                    }
                )
                findings.append(finding)
                logger.warning(f"Detected sensitive metadata: {key}")
            
            # Check for sensitive data patterns in values
            if isinstance(value, str):
                for data_type, pattern in SensitiveDataExposureDetector.SENSITIVE_PATTERNS.items():
                    if re.search(pattern, value, re.IGNORECASE):
                        finding = AtomicFinding(
                            id=f"metadata_sensitive_data_{source}_{key}",
                            finding_type=VulnerabilityType.SENSITIVE_DATA_EXPOSURE,
                            severity=SeverityLevel.HIGH,
                            source_node="server",
                            target_node=f"client",
                            description=f"{data_type.upper()} exposed in metadata: {key}",
                            confidence=0.85,
                            metadata={
                                'source': source,
                                'key': key,
                                'data_type': data_type
                            }
                        )
                        findings.append(finding)
                        logger.warning(f"Detected {data_type} in metadata: {key}")
                        break
        
        return findings

    @staticmethod
    def bulk_analyze(
        responses: List[Dict],
        endpoints: List[str]
    ) -> List[AtomicFinding]:
        """
        Analyze multiple responses for sensitive data exposure.
        
        Args:
            responses: List of response dicts with 'data' and 'endpoint' keys
            endpoints: List of endpoint information
            
        Returns:
            List of detected sensitive data exposures
        """
        findings = []
        
        for response in responses:
            endpoint = response.get('endpoint', 'unknown')
            data = response.get('data', '')
            is_public = response.get('is_public', False)
            
            # Check response body
            body_findings = SensitiveDataExposureDetector.detect_in_response(
                data, endpoint, "user", is_public
            )
            findings.extend(body_findings)
            
            # Check metadata
            if response.get('headers'):
                header_findings = SensitiveDataExposureDetector.detect_in_metadata(
                    response['headers'], 'http_headers'
                )
                findings.extend(header_findings)
            
            # Check debug info
            debug_finding = SensitiveDataExposureDetector.detect_debug_info_exposure(
                data, endpoint
            )
            if debug_finding:
                findings.append(debug_finding)
        
        logger.info(f"Bulk analysis found {len(findings)} sensitive data exposures")
        return findings
