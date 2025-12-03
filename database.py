"""
Database Configuration and Models
==================================
SQLite database setup for Hacking Tools Suite
"""

from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import json

db = SQLAlchemy()


class ScanResult(db.Model):
    """Store scan results and tool outputs."""
    __tablename__ = 'scan_results'
    
    id = db.Column(db.Integer, primary_key=True)
    tool_id = db.Column(db.String(100), nullable=False, index=True)
    tool_name = db.Column(db.String(200), nullable=False)
    target = db.Column(db.String(500))
    parameters = db.Column(db.Text)  # JSON string of parameters
    result_data = db.Column(db.Text)  # JSON string of results
    status = db.Column(db.String(50), default='success')  # success, error, warning
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    
    def to_dict(self):
        """Convert to dictionary."""
        return {
            'id': self.id,
            'tool_id': self.tool_id,
            'tool_name': self.tool_name,
            'target': self.target,
            'parameters': json.loads(self.parameters) if self.parameters else {},
            'result_data': json.loads(self.result_data) if self.result_data else {},
            'status': self.status,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }


class ToolUsage(db.Model):
    """Track tool usage statistics."""
    __tablename__ = 'tool_usage'
    
    id = db.Column(db.Integer, primary_key=True)
    tool_id = db.Column(db.String(100), nullable=False, index=True)
    tool_name = db.Column(db.String(200), nullable=False)
    category = db.Column(db.String(100), index=True)
    usage_count = db.Column(db.Integer, default=1)
    last_used = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    
    def to_dict(self):
        """Convert to dictionary."""
        return {
            'id': self.id,
            'tool_id': self.tool_id,
            'tool_name': self.tool_name,
            'category': self.category,
            'usage_count': self.usage_count,
            'last_used': self.last_used.isoformat() if self.last_used else None
        }


class SavedConfiguration(db.Model):
    """Store saved tool configurations."""
    __tablename__ = 'saved_configurations'
    
    id = db.Column(db.Integer, primary_key=True)
    tool_id = db.Column(db.String(100), nullable=False, index=True)
    config_name = db.Column(db.String(200), nullable=False)
    configuration = db.Column(db.Text)  # JSON string
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def to_dict(self):
        """Convert to dictionary."""
        return {
            'id': self.id,
            'tool_id': self.tool_id,
            'config_name': self.config_name,
            'configuration': json.loads(self.configuration) if self.configuration else {},
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }


class Session(db.Model):
    """Store user session data."""
    __tablename__ = 'sessions'
    
    id = db.Column(db.Integer, primary_key=True)
    session_id = db.Column(db.String(100), unique=True, nullable=False, index=True)
    data = db.Column(db.Text)  # JSON string
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, index=True)
    
    def to_dict(self):
        """Convert to dictionary."""
        return {
            'id': self.id,
            'session_id': self.session_id,
            'data': json.loads(self.data) if self.data else {},
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'expires_at': self.expires_at.isoformat() if self.expires_at else None
        }


def init_db(app):
    """Initialize the database."""
    with app.app_context():
        db.create_all()
        print("[*] Database initialized successfully")


def get_db_stats():
    """Get database statistics."""
    stats = {
        'total_scans': ScanResult.query.count(),
        'total_tools_used': ToolUsage.query.count(),
        'total_configs': SavedConfiguration.query.count(),
        'recent_scans': ScanResult.query.order_by(ScanResult.created_at.desc()).limit(10).all()
    }
    return stats

