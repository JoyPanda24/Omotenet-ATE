"""
Authentication Flaws Detection Module.
Detects authentication bypasses, weak authentication, and related issues.
"""
import logging
import hashlib
from typing import Dict, List, Optional
from ..core.data_models import AtomicFinding, VulnerabilityType, SeverityLevel

logger = logging.getLogger(__name__)


class AuthFlawsDetector:
    """Detects authentication-related vulnerabilities."""

    @staticmethod
    def detect_no_auth_required(
        endpoint: str,
        expected_auth: bool = True,
        data_sensitivity: int = 50
    ) -> Optional[AtomicFinding]:
        """
        Detect endpoints that should require authentication but don't.
        
        Args:
            endpoint: Endpoint URL/path
            expected_auth: Whether authentication should be required
            data_sensitivity: Sensitivity of data (0-100)
            
        Returns:
            AtomicFinding if auth flaw is detected
        """
        if expected_auth and data_sensitivity >= 50:
            severity = SeverityLevel.CRITICAL if data_sensitivity >= 80 else SeverityLevel.HIGH
            
            finding = AtomicFinding(
                id=f"auth_bypass_{endpoint.replace('/', '_')}",
                finding_type=VulnerabilityType.AUTHENTICATION_FLAW,
                severity=severity,
                source_node="unauthenticated",
                target_node=f"endpoint_{endpoint.replace('/', '_')}",
                description=f"No authentication required for sensitive endpoint: {endpoint}",
                confidence=1.0,
                metadata={
                    'endpoint': endpoint,
                    'data_sensitivity': data_sensitivity
                }
            )
            logger.warning(f"Detected authentication bypass: {endpoint}")
            return finding
        
        return None

    @staticmethod
    def detect_weak_token_scheme(
        token_scheme: str,
        token_example: str = None
    ) -> Optional[AtomicFinding]:
        """
        Detect weak or predictable token schemes.
        
        Args:
            token_scheme: Type of token scheme (e.g., 'jwt', 'bearer', 'basic', 'custom')
            token_example: Example token to analyze
            
        Returns:
            AtomicFinding if weak scheme is detected
        """
        weak_schemes = ['basic', 'custom', 'proprietary']
        
        if token_scheme.lower() in weak_schemes:
            finding = AtomicFinding(
                id=f"weak_auth_token_{token_scheme}",
                finding_type=VulnerabilityType.AUTHENTICATION_FLAW,
                severity=SeverityLevel.MEDIUM,
                source_node="attacker",
                target_node="auth_mechanism",
                description=f"Weak authentication token scheme detected: {token_scheme}",
                confidence=0.7,
                metadata={'token_scheme': token_scheme}
            )
            logger.warning(f"Detected weak token scheme: {token_scheme}")
            return finding
        
        return None

    @staticmethod
    def detect_session_fixation(
        session_id: str,
        can_set_own: bool = True
    ) -> Optional[AtomicFinding]:
        """
        Detect potential session fixation vulnerabilities.
        
        Args:
            session_id: Session identifier
            can_set_own: Whether attacker can set their own session ID
            
        Returns:
            AtomicFinding if session fixation is possible
        """
        if can_set_own:
            finding = AtomicFinding(
                id=f"session_fixation_{session_id}",
                finding_type=VulnerabilityType.AUTHENTICATION_FLAW,
                severity=SeverityLevel.HIGH,
                source_node="attacker",
                target_node="victim_user",
                description=f"Session fixation vulnerability: Attacker can set user session ID",
                confidence=0.9,
                metadata={'session_id_format': session_id}
            )
            logger.warning(f"Detected session fixation vulnerability")
            return finding
        
        return None

    @staticmethod
    def detect_cookie_issues(
        cookie_name: str,
        has_httponly: bool = False,
        has_secure: bool = False,
        samesite: str = None,
        is_sensitive: bool = True
    ) -> Optional[AtomicFinding]:
        """
        Detect insecure cookie configurations.
        
        Args:
            cookie_name: Name of the cookie
            has_httponly: Whether HttpOnly flag is set
            has_secure: Whether Secure flag is set
            samesite: SameSite attribute value
            is_sensitive: Whether this is a sensitive cookie (auth/session)
            
        Returns:
            AtomicFinding if insecure cookie is detected
        """
        if is_sensitive and (not has_httponly or not has_secure):
            severity = SeverityLevel.HIGH if is_sensitive else SeverityLevel.MEDIUM
            
            missing_flags = []
            if not has_httponly:
                missing_flags.append("HttpOnly")
            if not has_secure:
                missing_flags.append("Secure")
            if not samesite or samesite.lower() == 'none':
                missing_flags.append("SameSite")
            
            finding = AtomicFinding(
                id=f"insecure_cookie_{cookie_name}",
                finding_type=VulnerabilityType.AUTHENTICATION_FLAW,
                severity=severity,
                source_node="attacker",
                target_node=f"cookie_{cookie_name}",
                description=f"Insecure cookie {cookie_name} missing flags: {', '.join(missing_flags)}",
                confidence=0.95,
                metadata={
                    'cookie_name': cookie_name,
                    'missing_flags': missing_flags
                }
            )
            logger.warning(f"Detected insecure cookie: {cookie_name}")
            return finding
        
        return None

    @staticmethod
    def detect_brute_force_vulnerability(
        endpoint: str,
        rate_limit: int = 0,
        lockout_policy: bool = False
    ) -> Optional[AtomicFinding]:
        """
        Detect lack of brute-force protection.
        
        Args:
            endpoint: Authentication endpoint
            rate_limit: Requests per minute allowed (0 = unlimited)
            lockout_policy: Whether account lockout exists
            
        Returns:
            AtomicFinding if brute-force vulnerability exists
        """
        if rate_limit == 0 and not lockout_policy:
            finding = AtomicFinding(
                id=f"bruteforce_{endpoint.replace('/', '_')}",
                finding_type=VulnerabilityType.AUTHENTICATION_FLAW,
                severity=SeverityLevel.MEDIUM,
                source_node="attacker",
                target_node=f"endpoint_{endpoint.replace('/', '_')}",
                description=f"Brute-force vulnerability: No rate limiting on {endpoint}",
                confidence=0.9,
                metadata={'endpoint': endpoint}
            )
            logger.warning(f"Detected brute-force vulnerability: {endpoint}")
            return finding
        
        return None

    @staticmethod
    def bulk_analyze(auth_configs: List[Dict]) -> List[AtomicFinding]:
        """
        Analyze multiple authentication configurations.
        
        Args:
            auth_configs: List of authentication configuration dicts
            
        Returns:
            List of detected authentication flaws
        """
        findings = []
        
        for config in auth_configs:
            # Check for missing authentication
            if config.get('endpoint') and not config.get('requires_auth'):
                finding = AuthFlawsDetector.detect_no_auth_required(
                    endpoint=config['endpoint'],
                    expected_auth=True,
                    data_sensitivity=config.get('data_sensitivity', 50)
                )
                if finding:
                    findings.append(finding)
            
            # Check token scheme
            if config.get('token_scheme'):
                finding = AuthFlawsDetector.detect_weak_token_scheme(
                    config['token_scheme']
                )
                if finding:
                    findings.append(finding)
            
            # Check cookie security
            if config.get('cookies'):
                for cookie in config['cookies']:
                    finding = AuthFlawsDetector.detect_cookie_issues(
                        cookie.get('name'),
                        has_httponly=cookie.get('httponly', False),
                        has_secure=cookie.get('secure', False),
                        samesite=cookie.get('samesite'),
                        is_sensitive=cookie.get('is_sensitive', True)
                    )
                    if finding:
                        findings.append(finding)
        
        logger.info(f"Bulk analysis found {len(findings)} authentication vulnerabilities")
        return findings
