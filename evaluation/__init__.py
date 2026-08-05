"""
Evaluation module for model performance metrics and comparison.
"""

from .metrics import calculate_metrics
from .compare_models import compare_models

__all__ = ['calculate_metrics', 'compare_models']
