#!/usr/bin/env python3
"""
Enhanced Logging System for AWS Lambda Testing Toolkit
Provides structured logging, colored console output, progress tracking, and audit trails
"""

import logging
import json
import sys
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, Optional, Union
import uuid

try:
    from rich.console import Console
    from rich.progress import (
        Progress, TaskID, SpinnerColumn, TextColumn, 
        BarColumn, TimeElapsedColumn, MofNCompleteColumn
    )
    from rich.panel import Panel
    from rich.text import Text
    from rich.logging import RichHandler
    from rich.table import Table
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False
    # Fallback types when rich is not available
    Console = object
    TaskID = int


class LogLevel(Enum):
    """Log levels with enhanced categorization"""
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    SUCCESS = "SUCCESS"
    SECURITY = "SECURITY"
    PROGRESS = "PROGRESS"


class SecurityEventType(Enum):
    """Security event categories for audit logging"""
    CREDENTIAL_EXTRACTION = "credential_extraction"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DATA_ENUMERATION = "data_enumeration"
    WEB_SHELL_UPLOAD = "web_shell_upload"
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    COMPLIANCE_VIOLATION = "compliance_violation"
    LATERAL_MOVEMENT = "lateral_movement"


class JSONFormatter(logging.Formatter):
    """JSON formatter for structured audit logs"""
    
    def format(self, record):
        log_entry = {
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
            'module': record.module,
            'function': record.funcName,
            'line': record.lineno
        }
        
        # Add extra fields if available
        if hasattr(record, 'operation'):
            log_entry['operation'] = record.operation
        if hasattr(record, 'security_event'):
            log_entry['security_event'] = record.security_event
        if hasattr(record, 'correlation_id'):
            log_entry['correlation_id'] = record.correlation_id
        if hasattr(record, 'context'):
            log_entry['context'] = record.context
            
        return json.dumps(log_entry, default=str)


class ColoredFormatter(logging.Formatter):
    """Colored formatter for console output (fallback when rich is not available)"""
    
    # ANSI color codes
    COLORS = {
        'DEBUG': '\033[36m',     # Cyan
        'INFO': '\033[34m',      # Blue  
        'SUCCESS': '\033[32m',   # Green
        'WARNING': '\033[33m',   # Yellow
        'ERROR': '\033[31m',     # Red
        'SECURITY': '\033[35m',  # Magenta
        'RESET': '\033[0m'       # Reset
    }
    
    def format(self, record):
        color = self.COLORS.get(record.levelname, self.COLORS['RESET'])
        reset = self.COLORS['RESET']
        
        # Add timestamp
        timestamp = datetime.now().strftime('%H:%M:%S')
        
        # Format message with color
        message = f"{color}[{record.levelname}]{reset} {record.getMessage()}"
        
        if record.levelname in ['ERROR', 'SECURITY']:
            message = f"[{timestamp}] {message}"
            
        return message


class ProgressManager:
    """Progress tracking for long-running operations"""
    
    def __init__(self, console: Optional[Console] = None):
        self.console = console or (Console() if RICH_AVAILABLE else None)
        self.progress = None
        self.tasks = {}
        self.fallback_mode = not RICH_AVAILABLE
        
        if RICH_AVAILABLE and self.console:
            self.progress = Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(complete_style="green"),
                MofNCompleteColumn(),
                TimeElapsedColumn(),
                console=self.console
            )
        
    def __enter__(self):
        if self.progress:
            self.progress.start()
        return self
        
    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.progress:
            self.progress.stop()
            
    def start_operation(self, description: str, total: Optional[int] = None) -> TaskID:
        """Start a new progress-tracked operation"""
        if self.progress:
            task_id = self.progress.add_task(description, total=total)
            self.tasks[task_id] = {
                'description': description,
                'started': datetime.now(),
                'completed': False
            }
            return task_id
        else:
            # Fallback mode
            task_id = len(self.tasks)
            self.tasks[task_id] = {
                'description': description,
                'started': datetime.now(),
                'completed': False
            }
            print(f"🔄 {description}")
            return task_id
            
    def update_progress(self, task_id: TaskID, advance: int = 1, description: Optional[str] = None):
        """Update progress for an operation"""
        if self.progress:
            self.progress.update(task_id, advance=advance, description=description)
        if description and task_id in self.tasks:
            self.tasks[task_id]['description'] = description
            if self.fallback_mode:
                print(f"  ↳ {description}")
                
    def complete_operation(self, task_id: TaskID, success: bool = True, message: Optional[str] = None):
        """Mark an operation as complete"""
        if task_id in self.tasks:
            self.tasks[task_id]['completed'] = True
            self.tasks[task_id]['success'] = success
            
            elapsed = datetime.now() - self.tasks[task_id]['started']
            
            if self.progress:
                status = "✅ Complete" if success else "❌ Failed"
                final_desc = f"{status} - {message}" if message else status
                self.progress.update(task_id, description=final_desc, completed=100)
            elif self.fallback_mode:
                status = "✅" if success else "❌"
                duration = f"({elapsed.total_seconds():.1f}s)"
                final_msg = f" - {message}" if message else ""
                print(f"{status} {self.tasks[task_id]['description']} {duration}{final_msg}")


class UserFeedback:
    """Enhanced user feedback with rich formatting"""
    
    def __init__(self, console: Optional[Console] = None):
        self.console = console or (Console() if RICH_AVAILABLE else None)
        self.fallback_mode = not RICH_AVAILABLE
        
    def show_status(self, message: str, level: LogLevel = LogLevel.INFO, **kwargs):
        """Enhanced status display with colors and icons"""
        icons = {
            LogLevel.DEBUG: "🔍",
            LogLevel.INFO: "ℹ️",
            LogLevel.SUCCESS: "✅", 
            LogLevel.WARNING: "⚠️",
            LogLevel.ERROR: "❌",
            LogLevel.SECURITY: "🔒",
            LogLevel.PROGRESS: "🔄"
        }
        
        colors = {
            LogLevel.DEBUG: "dim cyan",
            LogLevel.INFO: "blue",
            LogLevel.SUCCESS: "green",
            LogLevel.WARNING: "yellow", 
            LogLevel.ERROR: "red",
            LogLevel.SECURITY: "magenta",
            LogLevel.PROGRESS: "cyan"
        }
        
        icon = icons.get(level, "•")
        
        if self.console and RICH_AVAILABLE:
            color = colors.get(level, "white")
            self.console.print(f"{icon} {message}", style=color)
        else:
            # Fallback mode
            print(f"{icon} {message}")
            
    def show_security_finding(self, finding: Dict[str, Any]):
        """Enhanced security finding display"""
        if self.console and RICH_AVAILABLE:
            severity_colors = {
                'HIGH': 'red',
                'MEDIUM': 'yellow', 
                'LOW': 'green',
                'CRITICAL': 'bold red'
            }
            
            severity = finding.get('severity', 'LOW').upper()
            color = severity_colors.get(severity, 'white')
            
            finding_text = Text()
            finding_text.append(f"{finding['type']}\n", style=f"bold {color}")
            finding_text.append(finding['description'], style=color)
            
            panel = Panel(
                finding_text,
                title=f"🚨 Security Finding - {severity}",
                border_style=color
            )
            
            self.console.print(panel)
        else:
            # Fallback mode
            severity = finding.get('severity', 'LOW').upper()
            print(f"\n🚨 Security Finding - {severity}")
            print(f"Type: {finding['type']}")
            print(f"Description: {finding['description']}")
            print("-" * 50)
            
    def show_table(self, title: str, data: list, headers: list):
        """Display data in a formatted table"""
        if self.console and RICH_AVAILABLE:
            table = Table(title=title)
            
            for header in headers:
                table.add_column(header, style="cyan", no_wrap=True)
                
            for row in data:
                table.add_row(*[str(item) for item in row])
                
            self.console.print(table)
        else:
            # Fallback mode - simple table
            print(f"\n{title}")
            print("-" * len(title))
            
            # Print headers
            header_row = " | ".join(f"{h:<15}" for h in headers)
            print(header_row)
            print("-" * len(header_row))
            
            # Print data rows
            for row in data:
                data_row = " | ".join(f"{str(item):<15}" for item in row)
                print(data_row)
            print()


class EnhancedLogger:
    """Main enhanced logger with structured logging and user feedback"""
    
    def __init__(self, name: str = "lambdalabs", log_level: int = logging.INFO, 
                 enable_file_logging: bool = True, log_directory: str = "logs"):
        self.name = name
        self.correlation_id = str(uuid.uuid4())[:8]
        
        # Initialize logger
        self.logger = logging.getLogger(name)
        self.logger.setLevel(log_level)
        
        # Clear existing handlers to avoid duplicates
        self.logger.handlers.clear()
        
        # Initialize console and feedback systems
        self.console = Console() if RICH_AVAILABLE else None
        self.user_feedback = UserFeedback(self.console)
        self.progress_manager = None
        
        # Setup logging handlers
        self._setup_console_logging()
        
        if enable_file_logging:
            self._setup_file_logging(log_directory)
            
    def _setup_console_logging(self):
        """Setup console logging with rich formatting or fallback"""
        if RICH_AVAILABLE and self.console:
            # Use Rich handler for beautiful console output
            rich_handler = RichHandler(
                console=self.console,
                show_path=False,
                rich_tracebacks=True,
                tracebacks_suppress=[
                    'click',
                    'rich'
                ]
            )
            rich_handler.setFormatter(logging.Formatter(
                fmt="%(message)s",
                datefmt="[%X]"
            ))
            self.logger.addHandler(rich_handler)
        else:
            # Fallback to colored console handler
            console_handler = logging.StreamHandler(sys.stdout)
            console_handler.setFormatter(ColoredFormatter())
            self.logger.addHandler(console_handler)
            
    def _setup_file_logging(self, log_directory: str):
        """Setup file-based audit logging"""
        try:
            log_dir = Path(log_directory)
            log_dir.mkdir(exist_ok=True)
            
            # Audit log file with structured JSON
            audit_file = log_dir / f"{self.name}_audit.log"
            file_handler = logging.FileHandler(audit_file)
            file_handler.setFormatter(JSONFormatter())
            file_handler.setLevel(logging.DEBUG)  # Capture everything in audit log
            
            self.logger.addHandler(file_handler)
            
            # Security events log
            security_file = log_dir / f"{self.name}_security.log"
            security_handler = logging.FileHandler(security_file)
            security_handler.setFormatter(JSONFormatter())
            security_handler.addFilter(lambda record: hasattr(record, 'security_event'))
            
            self.logger.addHandler(security_handler)
            
        except Exception as e:
            # If file logging fails, continue with console only
            self.info(f"File logging setup failed: {e}")
            
    def _create_log_record(self, level: str, message: str, **kwargs) -> logging.LogRecord:
        """Create a log record with enhanced metadata"""
        record = self.logger.makeRecord(
            self.logger.name, getattr(logging, level.upper()), 
            __file__, 0, message, (), None
        )
        
        # Add correlation ID
        record.correlation_id = self.correlation_id
        
        # Add extra context
        for key, value in kwargs.items():
            setattr(record, key, value)
            
        return record
        
    def debug(self, message: str, **kwargs):
        """Log debug message"""
        self.logger.debug(message, extra=kwargs)
        
    def info(self, message: str, show_user: bool = True, **kwargs):
        """Log info message with optional user display"""
        self.logger.info(message, extra=kwargs)
        if show_user:
            self.user_feedback.show_status(message, LogLevel.INFO)
            
    def success(self, message: str, show_user: bool = True, **kwargs):
        """Log success message"""
        # Create custom log level for success
        record = self._create_log_record('INFO', message, **kwargs)
        record.levelname = 'SUCCESS'
        self.logger.handle(record)
        
        if show_user:
            self.user_feedback.show_status(message, LogLevel.SUCCESS)
            
    def warning(self, message: str, show_user: bool = True, **kwargs):
        """Log warning message"""
        self.logger.warning(message, extra=kwargs)
        if show_user:
            self.user_feedback.show_status(message, LogLevel.WARNING)
            
    def error(self, message: str, show_user: bool = True, suggestion: Optional[str] = None, **kwargs):
        """Log error message with optional suggestion"""
        self.logger.error(message, extra=kwargs)
        
        if show_user:
            error_msg = message
            if suggestion:
                error_msg += f"\n💡 Suggestion: {suggestion}"
            self.user_feedback.show_status(error_msg, LogLevel.ERROR)
            
    def security_event(self, event_type: SecurityEventType, severity: str, 
                      description: str, details: Optional[Dict] = None, **kwargs):
        """Log security event for compliance and audit"""
        security_data = {
            'event_type': event_type.value,
            'severity': severity.upper(),
            'description': description,
            'details': details or {},
            'correlation_id': self.correlation_id
        }
        
        # Log to audit trail
        record = self._create_log_record('WARNING', description, **kwargs)
        record.security_event = event_type.value
        record.context = security_data
        self.logger.handle(record)
        
        # Display security finding to user
        finding = {
            'type': event_type.value.replace('_', ' ').title(),
            'severity': severity.upper(),
            'description': description
        }
        self.user_feedback.show_security_finding(finding)
        
    def operation_start(self, operation: str, description: str = None, **kwargs) -> str:
        """Start a tracked operation"""
        op_id = str(uuid.uuid4())[:8]
        
        self.logger.info(
            f"Operation started: {operation}",
            extra={
                'operation': operation,
                'operation_id': op_id,
                'status': 'started',
                'description': description,
                **kwargs
            }
        )
        
        return op_id
        
    def operation_complete(self, operation: str, operation_id: str, 
                          success: bool, message: str = None, **kwargs):
        """Complete a tracked operation"""
        status = 'success' if success else 'failed'
        
        self.logger.info(
            f"Operation {status}: {operation}",
            extra={
                'operation': operation,
                'operation_id': operation_id,
                'status': status,
                'message': message,
                **kwargs
            }
        )
        
        if success:
            self.success(message or f"{operation} completed successfully")
        else:
            self.error(message or f"{operation} failed")
            
    def start_progress(self) -> ProgressManager:
        """Start a progress tracking context"""
        self.progress_manager = ProgressManager(self.console)
        return self.progress_manager
        
    def show_table(self, title: str, data: list, headers: list):
        """Display formatted table"""
        self.user_feedback.show_table(title, data, headers)


# Singleton instance for global access
_global_logger: Optional[EnhancedLogger] = None


def get_logger(name: str = "lambdalabs", **kwargs) -> EnhancedLogger:
    """Get or create the global enhanced logger instance"""
    global _global_logger
    
    if _global_logger is None:
        _global_logger = EnhancedLogger(name=name, **kwargs)
    
    return _global_logger


def setup_logging(log_level: int = logging.INFO, enable_file_logging: bool = True, 
                 log_directory: str = "logs") -> EnhancedLogger:
    """Setup enhanced logging system"""
    global _global_logger
    
    _global_logger = EnhancedLogger(
        log_level=log_level,
        enable_file_logging=enable_file_logging,
        log_directory=log_directory
    )
    
    return _global_logger
