"""
Model comparison and visualization utilities.
"""

import logging
import pandas as pd

logger = logging.getLogger(__name__)


def create_comparison_table(models_metrics, model_names=None):
    """
    Create comparison table for multiple models.
    
    Args:
        models_metrics (list): List of metrics dictionaries for each model
        model_names (list): Names of models
        
    Returns:
        pd.DataFrame: Comparison table
    """
    if model_names is None:
        model_names = [f"Model_{i}" for i in range(len(models_metrics))]
    
    # Extract comparable metrics
    metrics_to_compare = ['accuracy', 'precision', 'recall', 'f1', 
                         'detection_rate', 'false_positive_rate']
    
    comparison_data = {}
    
    for model_name, metrics in zip(model_names, models_metrics):
        model_data = {}
        for metric in metrics_to_compare:
            if metric in metrics:
                model_data[metric] = metrics[metric]
        comparison_data[model_name] = model_data
    
    df_comparison = pd.DataFrame(comparison_data).T
    
    logger.info(f"Comparison table created for {len(model_names)} models")
    return df_comparison


def rank_models(models_metrics, model_names=None, metric_weights=None):
    """
    Rank models based on performance metrics.
    
    Args:
        models_metrics (list): List of metrics dictionaries
        model_names (list): Names of models
        metric_weights (dict): Custom weights for each metric
        
    Returns:
        pd.DataFrame: Ranked models with scores
    """
    if model_names is None:
        model_names = [f"Model_{i}" for i in range(len(models_metrics))]
    
    if metric_weights is None:
        # Default weights
        metric_weights = {
            'accuracy': 0.25,
            'precision': 0.2,
            'recall': 0.25,
            'f1': 0.15,
            'detection_rate': 0.1,
            'false_positive_rate': -0.05
        }
    
    scores = []
    
    for model_name, metrics in zip(model_names, models_metrics):
        weighted_score = 0.0
        
        for metric, weight in metric_weights.items():
            if metric in metrics and isinstance(metrics[metric], (int, float)):
                weighted_score += metrics[metric] * weight
        
        scores.append({
            'model': model_name,
            'score': weighted_score
        })
    
    df_ranking = pd.DataFrame(scores).sort_values('score', ascending=False).reset_index(drop=True)
    df_ranking['rank'] = range(1, len(df_ranking) + 1)
    
    logger.info(f"Models ranked. Top model: {df_ranking.iloc[0]['model']}")
    return df_ranking[['rank', 'model', 'score']]


def generate_comparison_report(models_metrics, model_names=None):
    """
    Generate comprehensive comparison report.
    
    Args:
        models_metrics (list): List of metrics dictionaries
        model_names (list): Names of models
        
    Returns:
        dict: Comprehensive comparison report
    """
    comparison_table = create_comparison_table(models_metrics, model_names)
    ranking = rank_models(models_metrics, model_names)
    
    report = {
        'comparison_table': comparison_table,
        'ranking': ranking,
        'best_model': ranking.iloc[0]['model'] if len(ranking) > 0 else None,
        'best_score': ranking.iloc[0]['score'] if len(ranking) > 0 else 0
    }
    
    logger.info(f"Comparison report generated. Best model: {report['best_model']}")
    return report
