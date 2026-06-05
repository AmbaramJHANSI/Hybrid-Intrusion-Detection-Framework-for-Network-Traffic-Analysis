"""
Reusable helper functions for the Dual IDS project.
"""

import logging
import json
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)


def setup_logging(log_dir='logs'):
    """
    Setup comprehensive logging configuration.
    
    Args:
        log_dir (str): Directory to store log files
    """
    Path(log_dir).mkdir(exist_ok=True)
    
    # Create formatters
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Set up file handler
    fh = logging.FileHandler(f'{log_dir}/dual_ids_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log')
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(formatter)
    
    # Get root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)
    root_logger.addHandler(fh)


def save_detection_alerts(alerts, output_file='logs/alerts.log'):
    """
    Save intrusion detection alerts to file.
    
    Args:
        alerts (list): List of detection alerts
        output_file (str): Output file path
    """
    try:
        Path(output_file).parent.mkdir(exist_ok=True)
        with open(output_file, 'a') as f:
            for alert in alerts:
                f.write(f"{datetime.now().isoformat()} - {json.dumps(alert)}\n")
        logger.info(f"Saved {len(alerts)} alerts to {output_file}")
    except Exception as e:
        logger.error(f"Error saving alerts: {e}")


def load_config(config_file):
    """
    Load configuration from JSON file.
    
    Args:
        config_file (str): Path to config JSON file
        
    Returns:
        dict: Configuration dictionary
    """
    try:
        with open(config_file, 'r') as f:
            config = json.load(f)
        logger.info(f"Configuration loaded from {config_file}")
        return config
    except Exception as e:
        logger.error(f"Error loading configuration: {e}")
        raise


def save_config(config, output_file='config.json'):
    """
    Save configuration to JSON file.
    
    Args:
        config (dict): Configuration dictionary
        output_file (str): Output file path
    """
    try:
        with open(output_file, 'w') as f:
            json.dump(config, f, indent=4)
        logger.info(f"Configuration saved to {output_file}")
    except Exception as e:
        logger.error(f"Error saving configuration: {e}")


def get_timestamp():
    """
    Get current timestamp in ISO format.
    
    Returns:
        str: Current timestamp
    """
    return datetime.now().isoformat()


def format_bytes(bytes_value):
    """
    Format bytes to human-readable format.
    
    Args:
        bytes_value (int): Size in bytes
        
    Returns:
        str: Formatted size string
    """
    for unit in ['B', 'KB', 'MB', 'GB']:
        if bytes_value < 1024.0:
            return f"{bytes_value:.2f}{unit}"
        bytes_value /= 1024.0
    return f"{bytes_value:.2f}TB"


def merge_results(signature_results, anomaly_results):
    """
    Merge signature and anomaly detection results.
    
    Args:
        signature_results (list): Signature detection results
        anomaly_results (list): Anomaly detection results
        
    Returns:
        list: Merged results
    """
    merged = []
    for sig, anom in zip(signature_results, anomaly_results):
        merged_result = {
            'signature': sig,
            'anomaly': anom,
            'timestamp': get_timestamp()
        }
        merged.append(merged_result)
    return merged
