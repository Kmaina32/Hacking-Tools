# Database Configuration

## Overview

The Hacking Tools Suite now uses **SQLite** database to store:
- Scan results and tool outputs
- Tool usage statistics
- Saved tool configurations
- Session data

## Database File

- **Location**: `hacking_tools.db` (in project root)
- **Type**: SQLite (lightweight, file-based database)
- **ORM**: Flask-SQLAlchemy

## Database Models

### 1. ScanResult
Stores scan results and tool outputs.

**Fields:**
- `id` - Primary key
- `tool_id` - Tool identifier (e.g., 'port_scanner')
- `tool_name` - Human-readable tool name
- `target` - Target host/domain/IP
- `parameters` - JSON string of input parameters
- `result_data` - JSON string of results
- `status` - 'success', 'error', or 'warning'
- `created_at` - Timestamp

### 2. ToolUsage
Tracks tool usage statistics.

**Fields:**
- `id` - Primary key
- `tool_id` - Tool identifier
- `tool_name` - Tool name
- `category` - Tool category
- `usage_count` - Number of times used
- `last_used` - Last usage timestamp

### 3. SavedConfiguration
Stores saved tool configurations for quick reuse.

**Fields:**
- `id` - Primary key
- `tool_id` - Tool identifier
- `config_name` - Configuration name
- `configuration` - JSON string of configuration
- `created_at` - Creation timestamp
- `updated_at` - Last update timestamp

### 4. Session
Stores user session data.

**Fields:**
- `id` - Primary key
- `session_id` - Unique session identifier
- `data` - JSON string of session data
- `created_at` - Creation timestamp
- `expires_at` - Expiration timestamp

## API Endpoints

### Database Statistics
```
GET /api/db/stats
```
Returns database statistics including total scans, tools used, and recent scans.

### Scan History
```
GET /api/db/scans?tool_id=<tool_id>&limit=<limit>
```
Get scan history. Optional filters:
- `tool_id` - Filter by specific tool
- `limit` - Maximum number of results (default: 50)

### Get Specific Scan
```
GET /api/db/scans/<scan_id>
```
Get a specific scan result by ID.

### Delete Scan
```
DELETE /api/db/scans/<scan_id>
```
Delete a scan result.

### Tool Usage Statistics
```
GET /api/db/usage?category=<category>
```
Get tool usage statistics. Optional filter:
- `category` - Filter by tool category

### Saved Configurations
```
GET /api/db/configs?tool_id=<tool_id>
POST /api/db/configs
DELETE /api/db/configs/<config_id>
```

**POST Body:**
```json
{
  "tool_id": "port_scanner",
  "config_name": "My Config",
  "configuration": {
    "ports": "1-1000",
    "timeout": 1,
    "threads": 50
  }
}
```

## Usage Examples

### Save Scan Result (Automatic)
Scan results are automatically saved when tools are used. For example, port scans are saved automatically.

### Track Tool Usage (Automatic)
Tool usage is automatically tracked when tools are executed.

### Manual Database Operations

**Initialize Database:**
```bash
python init_database.py
```

**Access Database Directly:**
```python
from app import app, db
from database import ScanResult

with app.app_context():
    # Get all scans
    scans = ScanResult.query.all()
    
    # Get scans for specific tool
    port_scans = ScanResult.query.filter_by(tool_id='port_scanner').all()
    
    # Get recent scans
    recent = ScanResult.query.order_by(ScanResult.created_at.desc()).limit(10).all()
```

## Database Location

The SQLite database file (`hacking_tools.db`) is created in the project root directory. You can:
- View it with SQLite browser tools
- Backup by copying the file
- Reset by deleting the file (it will be recreated on next run)

## Notes

- Database is automatically initialized on first app run
- All scan results are persisted automatically
- Tool usage statistics are tracked automatically
- Database file grows over time - consider periodic cleanup of old records

