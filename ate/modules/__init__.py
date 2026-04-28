"""ATE Modules - Vulnerability detection plugins."""

from .idor_detector import IDORDetector
from .auth_flaws import AuthFlawsDetector
from .sensitive_data_exposure import SensitiveDataExposureDetector

__all__ = [
    'IDORDetector',
    'AuthFlawsDetector',
    'SensitiveDataExposureDetector'
]
