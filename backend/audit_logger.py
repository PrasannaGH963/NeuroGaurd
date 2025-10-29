"""
Blockchain-inspired audit logging system with cryptographic integrity.
Each log entry contains hash of previous entry for tamper detection.
"""
import hashlib
import json
import uuid
import logging
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Tuple
from config import get_config


class AuditLogger:
    """
    Immutable audit log with cryptographic chain verification.
    Each entry hashes the previous entry to prevent tampering.
    """
    
    def __init__(self):
        """Initialize audit logger."""
        self.config = get_config()
        self.logs: List[Dict[str, Any]] = []
        self.previous_hash = "genesis_block_0x0000000000000000000000000000000000000000"
        self.stats = {
            'total_interactions': 0,
            'blocked_count': 0,
            'warned_count': 0,
            'allowed_count': 0,
            'security_alerts': 0,
        }
    
    def _calculate_hash(self, data: dict) -> str:
        """
        Calculate SHA-256 hash of log entry.
        
        Args:
            data: Log entry dictionary
            
        Returns:
            Hexadecimal hash string
        """
        # Sort keys for consistent hashing
        json_str = json.dumps(data, sort_keys=True, default=str)
        return hashlib.sha256(json_str.encode()).hexdigest()
    
    def _hash_string(self, text: str) -> str:
        """Hash a string using SHA-256."""
        return hashlib.sha256(text.encode()).hexdigest()
    
    def log_interaction(
        self,
        session_id: str,
        trust_score: int,
        trust_level: str,
        layers: List[Dict[str, Any]],
        action: str,
        prompt: str,
        response: Optional[str] = None,
        ml_classification: Optional[dict] = None,
        **metadata
    ) -> str:
        """
        Log a chat interaction with full security context.
        
        Args:
            session_id: User session identifier
            trust_score: Calculated trust score
            trust_level: Trust level (green/yellow/orange/red)
            layers: List of security layer results
            action: Action taken (allow/warn/restrict/block)
            prompt: User prompt (will be hashed)
            response: LLM response (will be hashed)
            ml_classification: ML classification results
            **metadata: Additional metadata (provider, latency, etc.)
            
        Returns:
            log_id: Unique identifier for this log entry
        """
        log_id = str(uuid.uuid4())
        timestamp = datetime.now(timezone.utc).isoformat()
        
        # Hash sensitive data
        prompt_hash = self._hash_string(prompt)
        response_hash = self._hash_string(response) if response else ""
        
        # Create log entry
        log_entry = {
            "log_id": log_id,
            "timestamp": timestamp,
            "previous_hash": self.previous_hash,
            "session_id": session_id,
            "event_type": "chat_interaction",
            "trust_score": trust_score,
            "trust_level": trust_level,
            "security_layers": layers,
            "prompt_hash": prompt_hash,
            "response_hash": response_hash,
            "action_taken": action,
            "metadata": {
                "provider": metadata.get("provider", "unknown"),
                "model": metadata.get("model", "unknown"),
                "latency_ms": metadata.get("latency_ms", 0),
                **{k: v for k, v in metadata.items() if k not in ["provider", "model", "latency_ms"]}
            }
        }
        
        if ml_classification:
            log_entry["ml_classification"] = ml_classification
        
        # Calculate hash of this entry
        log_entry["current_hash"] = self._calculate_hash(log_entry)
        
        # Append to logs
        self.logs.append(log_entry)
        
        # Update previous hash for next entry
        self.previous_hash = log_entry["current_hash"]
        
        # Update statistics
        self.stats['total_interactions'] += 1
        if action == 'block':
            self.stats['blocked_count'] += 1
        elif action == 'warn':
            self.stats['warned_count'] += 1
        elif action == 'allow':
            self.stats['allowed_count'] += 1
        
        # Limit in-memory logs
        if len(self.logs) > self.config.max_logs_in_memory:
            self.logs = self.logs[-self.config.max_logs_in_memory:]
        
        return log_id
    
    def log_security_event(
        self,
        session_id: str,
        event_type: str,
        severity: str,
        description: str,
        layers: List[Dict[str, Any]],
        **metadata
    ) -> str:
        """
        Log a security event (alert, incident, etc.).
        
        Args:
            session_id: User session identifier
            event_type: Type of event (security_alert, system_event, etc.)
            severity: Severity level (low, medium, high, critical)
            description: Event description
            layers: Relevant security layer results
            **metadata: Additional metadata
            
        Returns:
            log_id: Unique identifier for this log entry
        """
        log_id = str(uuid.uuid4())
        timestamp = datetime.now(timezone.utc).isoformat()
        
        log_entry = {
            "log_id": log_id,
            "timestamp": timestamp,
            "previous_hash": self.previous_hash,
            "session_id": session_id,
            "event_type": event_type,
            "severity": severity,
            "description": description,
            "security_layers": layers,
            "metadata": metadata
        }
        
        log_entry["current_hash"] = self._calculate_hash(log_entry)
        self.logs.append(log_entry)
        self.previous_hash = log_entry["current_hash"]
        
        if event_type == "security_alert":
            self.stats['security_alerts'] += 1
        
        if len(self.logs) > self.config.max_logs_in_memory:
            self.logs = self.logs[-self.config.max_logs_in_memory:]
        
        return log_id
    
    def verify_chain(self, start_index: int = 0, end_index: Optional[int] = None) -> Tuple[bool, List[str]]:
        """
        Verify integrity of audit log chain.
        
        Args:
            start_index: Starting index for verification
            end_index: Ending index (None for all)
            
        Returns:
            Tuple of (is_valid: bool, errors: List[str])
        """
        if not self.config.enable_chain_verification:
            return True, []
        
        errors = []
        logs_to_check = self.logs[start_index:end_index] if end_index else self.logs[start_index:]
        
        if not logs_to_check:
            return True, []
        
        # Check first entry points to previous hash
        if start_index == 0 and logs_to_check:
            expected_prev = self.logs[0].get("previous_hash")
            # For genesis, we allow any starting hash
        
        # Check each entry
        for i in range(len(logs_to_check)):
            entry = logs_to_check[i]
            
            # Verify current hash
            entry_copy = entry.copy()
            stored_hash = entry_copy.pop("current_hash")
            calculated_hash = self._calculate_hash(entry_copy)
            
            if stored_hash != calculated_hash:
                errors.append(f"Hash mismatch at index {start_index + i}: stored={stored_hash[:16]}..., calculated={calculated_hash[:16]}...")
                continue
            
            # Verify previous hash chain (except first entry)
            if i > 0:
                prev_entry = logs_to_check[i - 1]
                expected_prev_hash = prev_entry.get("current_hash")
                actual_prev_hash = entry.get("previous_hash")
                
                if expected_prev_hash != actual_prev_hash:
                    errors.append(f"Chain break at index {start_index + i}: expected previous_hash={expected_prev_hash[:16]}..., got={actual_prev_hash[:16]}...")
        
        return len(errors) == 0, errors
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get audit log statistics.
        
        Returns:
            Dictionary with statistics
        """
        total = self.stats['total_interactions']
        blocked_ratio = (self.stats['blocked_count'] / total * 100) if total > 0 else 0.0
        
        avg_trust_scores = []
        for log in self.logs:
            if log.get('event_type') == 'chat_interaction' and 'trust_score' in log:
                avg_trust_scores.append(log['trust_score'])
        
        avg_trust = sum(avg_trust_scores) / len(avg_trust_scores) if avg_trust_scores else 0
        
        return {
            **self.stats,
            'blocked_percentage': round(blocked_ratio, 2),
            'average_trust_score': round(avg_trust, 2),
            'total_logs': len(self.logs),
            'chain_verified': self.verify_chain()[0]
        }
    
    def export_logs(
        self, 
        filepath: str = "audit_logs.json",
        start_index: int = 0,
        end_index: Optional[int] = None
    ) -> str:
        """
        Export logs to JSON file.
        
        Args:
            filepath: Output file path
            start_index: Starting log index
            end_index: Ending log index (None for all)
            
        Returns:
            File path where logs were exported
        """
        logs_to_export = self.logs[start_index:end_index] if end_index else self.logs[start_index:]
        
        export_data = {
            "export_timestamp": datetime.now(timezone.utc).isoformat(),
            "total_entries": len(logs_to_export),
            "start_index": start_index,
            "end_index": end_index if end_index else len(self.logs),
            "chain_verified": self.verify_chain(start_index, end_index)[0],
            "logs": logs_to_export
        }
        
        with open(filepath, 'w') as f:
            json.dump(export_data, f, indent=2, default=str)
        
        return filepath
    
    def get_logs(
        self,
        session_id: Optional[str] = None,
        event_type: Optional[str] = None,
        limit: int = 100,
        offset: int = 0
    ) -> List[Dict[str, Any]]:
        """
        Get filtered logs.
        
        Args:
            session_id: Filter by session ID
            event_type: Filter by event type
            limit: Maximum number of logs to return
            offset: Offset for pagination
            
        Returns:
            List of log entries
        """
        filtered = self.logs
        
        if session_id:
            filtered = [log for log in filtered if log.get('session_id') == session_id]
        
        if event_type:
            filtered = [log for log in filtered if log.get('event_type') == event_type]
        
        # Sort by timestamp (newest first)
        filtered.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
        
        return filtered[offset:offset + limit]

