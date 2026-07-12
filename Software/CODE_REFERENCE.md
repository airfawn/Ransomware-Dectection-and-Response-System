# RDRS Module 1: Code Reference Guide

## Overview of Every File

### 1. `main.py` - Application Entry Point

**Purpose:** Initialize the system and handle user interaction

**Key Components:**

#### CLI Argument Parser
```python
def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="RDRS File System Monitor: watch file create/delete events in real time."
    )
    parser.add_argument(
        "--path",
        type=Path,
        default=Path.cwd(),
        help="Directory to monitor. Defaults to the current working directory.",
    )
    parser.add_argument(
        "--recursive",
        action="store_true",
        help="Monitor directories recursively.",
    )
    return parser.parse_args()
```

**Usage Examples:**

```bash
# Monitor current directory
python main.py

# Monitor specific directory
python main.py --path /tmp

# Monitor recursively
python main.py --path ~ --recursive

# Help
python main.py --help
```

#### Main Function
```python
def main() -> None:
    args = parse_args()
    logger = setup_logger()
    monitor = FileSystemMonitor(target_path=args.path, recursive=args.recursive, logger=logger)
    
    logger.info("Starting RDRS filesystem monitor for %s", args.path)
    try:
        monitor.start()
        monitor.join()
    except KeyboardInterrupt:
        logger.info("Stopping monitor due to user interrupt.")
    finally:
        monitor.stop()
```

**Execution Flow:**
1. Parse CLI arguments
2. Setup logger
3. Create FileSystemMonitor instance
4. Start monitoring (start())
5. Wait for events (join())
6. Handle Ctrl+C gracefully
7. Clean shutdown (stop())

---

### 2. `monitor/filesystem_monitor.py` - Core Monitoring Logic

**Purpose:** Capture filesystem events and enrich with process information

#### ProcessMetadata (Data Container)
```python
@dataclass(frozen=True)
class ProcessMetadata:
    """Process metadata captured for an event."""
    pid: Optional[int]           # Process ID (e.g., 1234)
    name: Optional[str]          # Process name (e.g., "python")
    executable: Optional[str]    # Full path (e.g., "/usr/bin/python3.11")
    parent_name: Optional[str]   # Parent process (e.g., "bash")
```

**Design Rationale:**
- `frozen=True` - Prevents accidental modification
- `Optional` fields - Handles "Unknown" scenarios gracefully
- Immutable - Thread-safe for concurrent access
- Clear types - Self-documenting

#### ProcessResolver (Best-Effort Process Lookup)
```python
class ProcessResolver:
    """Resolve process metadata for a filesystem event."""
    
    @staticmethod
    def resolve(path: Path) -> ProcessMetadata:
        """Return process metadata for the file at path."""
        normalized_target = ProcessResolver._normalize_path(path)
        
        for process in psutil.process_iter(["pid", "name", "exe", "ppid"]):
            try:
                for open_file in process.open_files():
                    if ProcessResolver._normalize_path(Path(open_file.path)) == normalized_target:
                        parent_name = ProcessResolver._get_parent_name(process)
                        return ProcessMetadata(
                            pid=process.pid,
                            name=process.name(),
                            executable=process.exe() if process.exe() else None,
                            parent_name=parent_name,
                        )
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                continue
            except Exception:
                continue
        
        # Fallback for unknown process
        return ProcessMetadata(pid=None, name=None, executable=None, parent_name=None)
```

**Algorithm:**
1. Normalize target file path (handle platform differences)
2. Iterate through all running processes
3. For each process, check its open files
4. Compare normalized paths
5. Return metadata if match found
6. Return "Unknown" if no match

**Why This Approach?**
- Watchdog events don't include PID
- Process may have already closed the file
- Some processes hide their operations
- Cross-platform compatibility

#### FileSystemMonitorHandler (Event Handler)
```python
class FileSystemMonitorHandler(FileSystemEventHandler):
    """Watchdog event handler for file creation and deletion."""
    
    def __init__(self, logger):
        super().__init__()
        self.logger = logger
    
    def on_created(self, event: FileCreatedEvent) -> None:
        if event.is_directory:
            return
        self._report_event("FILE CREATED", event.src_path)
    
    def on_deleted(self, event: FileDeletedEvent) -> None:
        if event.is_directory:
            return
        self._report_event("FILE DELETED", event.src_path)
    
    def _report_event(self, event_type: str, src_path: str) -> None:
        try:
            path = Path(src_path)
            event_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            process_metadata = ProcessResolver.resolve(path)
            
            output = ["=" * 38]
            output.append(f"EVENT: {event_type}")
            output.append("")
            output.append("Time:")
            output.append(event_time)
            # ... more fields ...
            output.append("=" * 38)
            
            self.logger.info("\n" + "\n".join(output))
        except Exception as exc:
            self.logger.error("Failed to report filesystem event for %s: %s", src_path, exc)
```

**Event Filtering:**
- `event.is_directory` check - Monitor files only, not directories
- Returns early if directory - Avoids unnecessary processing

**Error Handling:**
- Try-except wrapper - Prevents one bad event from crashing system
- Logs error for debugging - Helps troubleshoot issues

#### FileSystemMonitor (Main Orchestrator)
```python
class FileSystemMonitor:
    """Main monitor class for watching filesystem changes."""
    
    def __init__(self, target_path: Path, recursive: bool, logger):
        self.target_path = target_path
        self.recursive = recursive
        self.logger = logger
        self.observer = Observer()
        self.handler = FileSystemMonitorHandler(logger=self.logger)
    
    def start(self) -> None:
        if not self.target_path.exists():
            raise FileNotFoundError(f"Monitor path does not exist: {self.target_path}")
        
        self.observer.schedule(self.handler, str(self.target_path), recursive=self.recursive)
        self.observer.start()
        self.logger.info("Monitoring %s (recursive=%s)", self.target_path, self.recursive)
    
    def stop(self) -> None:
        self.observer.stop()
        self.observer.join(timeout=5)
    
    def join(self) -> None:
        try:
            while self.observer.is_alive():
                self.observer.join(timeout=1)
        except KeyboardInterrupt:
            self.stop()
```

**Key Responsibilities:**
1. Validate target path exists
2. Schedule event handler with watchdog
3. Start observer thread
4. Wait for events gracefully
5. Handle Ctrl+C
6. Stop observer cleanly

---

### 3. `utils/logger.py` - Logging Configuration

**Purpose:** Centralized logging for entire system

```python
def setup_logger() -> logging.Logger:
    """Create a logger configured for console output."""
    logger = logging.getLogger("rdrs")
    logger.setLevel(logging.INFO)
    
    if not logger.handlers:
        handler = logging.StreamHandler()
        formatter = logging.Formatter(
            fmt="%(asctime)s %(levelname)s %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
    
    return logger
```

**Configuration:**
- Logger Name: "rdrs" (prevents conflicts)
- Level: INFO (shows important events)
- Output: Console (stdout)
- Format: `[timestamp] [level] message`

**Usage Throughout System:**
```python
# In any module
from utils.logger import setup_logger

logger = setup_logger()
logger.info("System started")
logger.warning("Something unusual")
logger.error("An error occurred")
```

**Future Extensibility:**
```python
# Add file handler
file_handler = logging.FileHandler("rdrs.log")
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)

# Add syslog handler
import logging.handlers
syslog_handler = logging.handlers.SysLogHandler("/dev/log")
logger.addHandler(syslog_handler)
```

---

## Complete Usage Examples

### Example 1: Monitor Current Directory
```bash
cd /path/to/project
python main.py
```

**What happens:**
1. Monitor starts on current working directory
2. Watchdog listens for file events
3. Any file creation/deletion triggers handler
4. Process info is collected
5. Event is formatted and printed

**Example Output:**
```
[2026-07-12 15:42:18] [INFO] Starting RDRS filesystem monitor for /Users/adi
[2026-07-12 15:42:20] [INFO] ======================================
[2026-07-12 15:42:20] [INFO] EVENT: FILE CREATED
[2026-07-12 15:42:20] [INFO] 
[2026-07-12 15:42:20] [INFO] Time:
[2026-07-12 15:42:20] [INFO] 2026-07-12 15:42:20
```

### Example 2: Monitor System Temp Directory Recursively
```bash
python main.py --path /tmp --recursive
```

**What happens:**
1. Monitor starts on /tmp
2. Recursion enabled - watches subdirectories too
3. Any file operation in /tmp or subdirs is captured

### Example 3: Programmatic Usage
```python
from pathlib import Path
from monitor.filesystem_monitor import FileSystemMonitor
from utils.logger import setup_logger

# Setup
logger = setup_logger()
monitor = FileSystemMonitor(
    target_path=Path("/home/user/Downloads"),
    recursive=True,
    logger=logger
)

# Run
try:
    monitor.start()
    monitor.join()
except KeyboardInterrupt:
    print("Stopped by user")
finally:
    monitor.stop()
```

---

## Extension Examples

### Extension 1: Add File Modification Monitoring
```python
# In FileSystemMonitorHandler
def on_modified(self, event: FileModifiedEvent) -> None:
    if event.is_directory:
        return
    self._report_event("FILE MODIFIED", event.src_path)
```

### Extension 2: Add File Rename Monitoring
```python
# In FileSystemMonitorHandler
def on_moved(self, event: FileMovedEvent) -> None:
    if event.is_directory:
        return
    # Report the destination path where file was moved to
    self._report_event("FILE MOVED", event.dest_path)
```

### Extension 3: Add Entropy Analysis
```python
# New file: analysis/entropy.py
import math
from pathlib import Path

class EntropyCalculator:
    @staticmethod
    def calculate(file_path: Path) -> float:
        """Calculate Shannon entropy of file."""
        if not file_path.exists():
            return 0.0
        
        with open(file_path, 'rb') as f:
            data = f.read()
        
        if not data:
            return 0.0
        
        # Calculate frequency of each byte
        frequencies = {}
        for byte in data:
            frequencies[byte] = frequencies.get(byte, 0) + 1
        
        # Calculate entropy
        entropy = 0.0
        data_len = len(data)
        for freq in frequencies.values():
            probability = freq / data_len
            entropy -= probability * math.log2(probability)
        
        return entropy
```

### Extension 4: Add Behavior Scoring
```python
# New file: analysis/scorer.py
class BehaviorScorer:
    def __init__(self):
        self.entropy_threshold = 7.5
        self.rapid_creation_threshold = 10  # files in 10 seconds
    
    def score_event(self, event_metadata: dict) -> float:
        """Score event for ransomware likelihood (0.0 - 1.0)."""
        score = 0.0
        
        # Check process
        if event_metadata['process_name'] == 'Unknown':
            score += 0.2  # Unknown process is suspicious
        
        # Check file extension
        suspicious_extensions = ['.encrypted', '.locked', '.ransom']
        if any(event_metadata['filename'].endswith(ext) 
               for ext in suspicious_extensions):
            score += 0.5
        
        return min(score, 1.0)
```

### Extension 5: Add Quarantine System
```python
# New file: response/quarantine.py
import shutil
from pathlib import Path

class FileQuarantine:
    def __init__(self, quarantine_dir: Path):
        self.quarantine_dir = quarantine_dir
        self.quarantine_dir.mkdir(exist_ok=True)
    
    def isolate(self, file_path: Path) -> bool:
        """Move suspicious file to quarantine."""
        try:
            quarantine_path = self.quarantine_dir / file_path.name
            shutil.move(str(file_path), str(quarantine_path))
            return True
        except Exception as e:
            print(f"Failed to quarantine: {e}")
            return False
```

---

## Data Flow Diagrams

### File Creation Event Flow
```
File Created
    │
    ▼
Watchdog detects event
    │
    ▼
FileSystemEventHandler.on_created(event)
    │
    ├─ Is directory? → EXIT
    │
    ▼
Extract path: event.src_path
    │
    ▼
ProcessResolver.resolve(path)
    │
    ├─ Normalize path
    ├─ Iterate processes
    ├─ Find open files
    └─ Return metadata
    │
    ▼
Format output with all info
    │
    ├─ Event type
    ├─ Timestamp
    ├─ File path
    ├─ File name
    ├─ Process ID
    ├─ Process name
    ├─ Process executable
    └─ Parent process
    │
    ▼
Log to console via logger
    │
    ▼
Continue monitoring
```

---

## Common Issues and Solutions

### Issue: "AttributeError: module 'watchdog.events' has no attribute 'FileModifiedEvent'"
**Cause:** Using an incompatible watchdog version
**Solution:** Install correct version: `pip install watchdog==6.0.0`

### Issue: "No module named 'psutil'"
**Cause:** Dependencies not installed
**Solution:** Run `pip install -r requirements.txt`

### Issue: "Permission denied" in process lookup
**Cause:** System process requires elevated privileges
**Solution:** Run with sudo: `sudo python main.py --path /path`

### Issue: No events being captured
**Cause:** Monitoring wrong directory or watching wrong event type
**Solution:** Test with: `echo "test" > /tmp/test.txt && rm /tmp/test.txt`

---

## Performance Optimization Tips

### For Large Directories
```python
# Use non-recursive monitoring if possible
monitor = FileSystemMonitor(target_path=path, recursive=False, logger=logger)
```

### For Multiple Paths
```python
# Create multiple monitors (future enhancement)
monitors = [
    FileSystemMonitor(Path(p), False, logger)
    for p in ['/tmp', '/home', '/var']
]
```

### For Network Shares
```python
# NFS/Samba may be slow, consider excluding
# Monitor local directories only
monitor = FileSystemMonitor(Path('/local/path'), recursive=False, logger=logger)
```

---

## Type Hints Reference

All functions use type hints for clarity:

```python
# Function with type hints
def resolve(path: Path) -> ProcessMetadata:
    # Argument: path is a Path object
    # Returns: ProcessMetadata object
    pass

# Optional types
def get_parent_name(process: psutil.Process) -> Optional[str]:
    # May return string or None
    pass

# Collection types
def on_created(self, event: FileCreatedEvent) -> None:
    # Takes FileCreatedEvent, returns nothing
    pass
```

---

## Final Thoughts

This codebase demonstrates:
- ✅ Production-quality Python
- ✅ Proper error handling
- ✅ Clear architecture
- ✅ Extensible design
- ✅ Comprehensive logging
- ✅ Cross-platform support

Use this as a foundation for:
- Learning advanced Python
- Building security tools
- Understanding EDR systems
- Implementing ransomware detection

---

**Document Version:** 1.0.0
**Last Updated:** July 2026
