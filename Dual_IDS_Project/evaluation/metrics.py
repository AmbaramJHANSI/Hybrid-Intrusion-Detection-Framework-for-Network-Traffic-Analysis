"""
Performance metrics calculation for intrusion detection models.
"""

import logging
import numpy as np
from sklearn.metrics import (confusion_matrix, accuracy_score, precision_score,
                            recall_score, f1_score, roc_auc_score, roc_curve,
                            auc, classification_report)

logger = logging.getLogger(__name__)


def calculate_confusion_matrix(y_true, y_pred):
    """
    Calculate confusion matrix components.
    
    Args:
        y_true (array-like): True labels
        y_pred (array-like): Predicted labels
        
    Returns:
        dict: TP, TN, FP, FN values
    """
    cm = confusion_matrix(y_true, y_pred)
    tn, fp, fn, tp = cm.ravel()
    
    return {
        'true_positives': tp,
        'true_negatives': tn,
        'false_positives': fp,
        'false_negatives': fn
    }


def calculate_metrics(y_true, y_pred, y_pred_proba=None):
    """
    Calculate comprehensive evaluation metrics.
    
    Args:
        y_true (array-like): True labels
        y_pred (array-like): Predicted labels
        y_pred_proba (array-like): Prediction probabilities (optional)
        
    Returns:
        dict: Comprehensive metrics including accuracy, precision, recall, etc.
    """
    metrics = {}
    
    try:
        # Basic metrics
        metrics['accuracy'] = accuracy_score(y_true, y_pred)
        metrics['precision'] = precision_score(y_true, y_pred, average='weighted', zero_division=0)
        metrics['recall'] = recall_score(y_true, y_pred, average='weighted', zero_division=0)
        metrics['f1'] = f1_score(y_true, y_pred, average='weighted', zero_division=0)
        
        # Detection rate (DR) and False Positive Rate (FPR)
        cm_dict = calculate_confusion_matrix(y_true, y_pred)
        tp = cm_dict['true_positives']
        tn = cm_dict['true_negatives']
        fp = cm_dict['false_positives']
        fn = cm_dict['false_negatives']
        
        metrics['detection_rate'] = tp / (tp + fn) if (tp + fn) > 0 else 0
        metrics['false_positive_rate'] = fp / (fp + tn) if (fp + tn) > 0 else 0
        metrics['true_negative_rate'] = tn / (tn + fp) if (tn + fp) > 0 else 0
        
        # Confusion matrix components
        metrics.update(cm_dict)
        
        # ROC-AUC if probabilities provided
        if y_pred_proba is not None:
            try:
                metrics['auc'] = roc_auc_score(y_true, y_pred_proba)
                fpr, tpr, _ = roc_curve(y_true, y_pred_proba)
                metrics['fpr'] = fpr
                metrics['tpr'] = tpr
            except Exception as e:
                logger.warning(f"Could not calculate ROC-AUC: {e}")
        
        logger.info(f"Metrics calculated - Accuracy: {metrics['accuracy']:.4f}, "
                   f"Detection Rate: {metrics['detection_rate']:.4f}, "
                   f"FPR: {metrics['false_positive_rate']:.4f}")
        
        return metrics
    except Exception as e:
        logger.error(f"Error calculating metrics: {e}")
        raise


def get_classification_report(y_true, y_pred, target_names=None):
    """
    Generate classification report.
    
    Args:
        y_true (array-like): True labels
        y_pred (array-like): Predicted labels
        target_names (list): Names of target classes
        
    Returns:
        str: Formatted classification report
    """
    report = classification_report(y_true, y_pred, target_names=target_names)
    logger.info("Classification report generated")
    return report
