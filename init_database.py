"""
Database Initialization Script
===============================
Run this script to initialize or reset the database
"""

from app import app, db
from database import ScanResult, ToolUsage, SavedConfiguration, Session

def init_database():
    """Initialize the database."""
    with app.app_context():
        # Drop all tables (use with caution!)
        # db.drop_all()
        
        # Create all tables
        db.create_all()
        print("[*] Database tables created successfully")
        
        # Get statistics
        stats = {
            'scan_results': ScanResult.query.count(),
            'tool_usage': ToolUsage.query.count(),
            'saved_configs': SavedConfiguration.query.count(),
            'sessions': Session.query.count()
        }
        
        print(f"[*] Database Statistics:")
        print(f"    - Scan Results: {stats['scan_results']}")
        print(f"    - Tool Usage Records: {stats['tool_usage']}")
        print(f"    - Saved Configurations: {stats['saved_configs']}")
        print(f"    - Sessions: {stats['sessions']}")
        print("[*] Database ready!")

if __name__ == '__main__':
    init_database()

