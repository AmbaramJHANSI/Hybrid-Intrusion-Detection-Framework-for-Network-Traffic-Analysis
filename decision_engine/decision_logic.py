"""
Decision logic combining signature-based and anomaly-based detection results.
"""
import logging
logger = logging.getLogger(__name__)
class DecisionEngine:
    """Combines outputs from signature and anomaly detection modules."""

    def __init__(self, signature_weight=0.4, anomaly_weight=0.6):
        """
        Initialize DecisionEngine.
        
        Args:
            signature_weight (float): Weight for signature detection (0-1)
            anomaly_weight (float): Weight for anomaly detection (0-1)
        """
        self.signature_weight = signature_weight
        self.anomaly_weight = anomaly_weight
        
        # Normalize weights
        total_weight = signature_weight + anomaly_weight
        self.signature_weight /= total_weight
        self.anomaly_weight /= total_weight
        
        logger.info(f"DecisionEngine initialized - Signature weight: {self.signature_weight:.2f}, "
                   f"Anomaly weight: {self.anomaly_weight:.2f}")
    def combine_detections(self, signature_result, anomaly_result):
        """
        Combine results from both detection methods.
        Args:
            signature_result (dict): Output from SignatureDetector
            anomaly_result (dict): Output from AnomalyDetector
        Returns:
            dict: Final intrusion detection decision
        """
        # Calculate threat score
        signature_score = 1.0 if signature_result.get('is_anomaly', False) else 0.0
        anomaly_score = anomaly_result.get('anomaly_score', 0.0)
        
        # Weighted combination
        combined_score = (self.signature_weight * signature_score + 
                         self.anomaly_weight * anomaly_score)
        
        # Determine final decision
        is_intrusion = combined_score > 0.5
        
        decision = {
            'is_intrusion': is_intrusion,
            'combined_score': combined_score,
            'signature_detection': signature_result,
            'anomaly_detection': anomaly_result,
            'confidence': max(signature_score, anomaly_score),
            'decision_threshold': 0.5
        }
        
        # Log critical detections
        if is_intrusion:
            threat_level = self._determine_threat_level(combined_score)
            decision['threat_level'] = threat_level
            logger.warning(f"Intrusion detected! Threat level: {threat_level}, "
                          f"Score: {combined_score:.3f}")
        
        return decision
    
    def _determine_threat_level(self, score):
        """
        Determine threat level based on combined score.
        
        Args:
            score (float): Combined detection score
            
        Returns:
            str: Threat level ('low', 'medium', 'high', 'critical')
        """
        if score < 0.5:
            return 'low'
        elif score < 0.65:
            return 'medium'
        elif score < 0.85:
            return 'high'
        else:
            return 'critical'
    
    def batch_decide(self, signature_results, anomaly_results):
        """
        Combine results for multiple records.
        
        Args:
            signature_results (list): List of signature detection results
            anomaly_results (list): List of anomaly detection results
            
        Returns:
            list: Final decisions for each record
        """
        decisions = []
        
        for sig_result, anom_result in zip(signature_results, anomaly_results):
            decision = self.combine_detections(sig_result, anom_result)
            decisions.append(decision)
        
        logger.info(f"Batch decision completed for {len(decisions)} records")
        return decisions
    
    def set_weights(self, signature_weight, anomaly_weight):
        """
        Update detection method weights.
        
        Args:
            signature_weight (float): New signature weight
            anomaly_weight (float): New anomaly weight
        """
        total_weight = signature_weight + anomaly_weight
        self.signature_weight = signature_weight / total_weight
        self.anomaly_weight = anomaly_weight / total_weight
        logger.info(f"Weights updated - Signature: {self.signature_weight:.2f}, "
                   f"Anomaly: {self.anomaly_weight:.2f}")
