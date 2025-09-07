#!/usr/bin/env python3
"""
Output Preferences Configuration for LambdaLabs
Manages user-configurable output settings and verbosity levels
"""

import os
from enum import Enum
from typing import Dict, Any
from pathlib import Path


class VerbosityLevel(Enum):
    """User-configurable verbosity levels"""
    MINIMAL = "minimal"     # Only critical info and results
    NORMAL = "normal"       # Standard operational info
    DETAILED = "detailed"   # Enhanced operational details
    DEBUG = "debug"         # Full debug information


class OutputFormat(Enum):
    """Output format options"""
    RICH = "rich"           # Rich console with colors and formatting
    PLAIN = "plain"         # Plain text without special formatting
    JSON = "json"           # JSON structured output


class OutputPreferences:
    """User output configuration and preferences"""
    
    def __init__(self):
        """Initialize with default preferences"""
        self.verbosity_level = VerbosityLevel.NORMAL
        self.output_format = OutputFormat.RICH
        self.show_timestamps = True
        self.colored_output = True
        self.show_progress_bars = True
        self.show_security_warnings = True
        self.show_cost_warnings = True
        self.show_performance_metrics = False
        self.max_table_rows = 50
        self.truncate_long_output = True
        self.save_to_file = True
        
        # Load from environment variables if set
        self._load_from_environment()
        
        # Load from config file if exists
        self._load_from_config_file()
        
    def _load_from_environment(self):
        """Load preferences from environment variables"""
        env_mappings = {
            'LAMBDALABS_VERBOSITY': 'verbosity_level',
            'LAMBDALABS_FORMAT': 'output_format',
            'LAMBDALABS_TIMESTAMPS': 'show_timestamps',
            'LAMBDALABS_COLORS': 'colored_output',
            'LAMBDALABS_PROGRESS': 'show_progress_bars'
        }
        
        for env_var, attr_name in env_mappings.items():
            env_value = os.getenv(env_var)
            if env_value:
                try:
                    if attr_name == 'verbosity_level':
                        self.verbosity_level = VerbosityLevel(env_value.lower())
                    elif attr_name == 'output_format':
                        self.output_format = OutputFormat(env_value.lower())
                    elif attr_name in ['show_timestamps', 'colored_output', 'show_progress_bars']:
                        setattr(self, attr_name, env_value.lower() in ['true', '1', 'yes'])
                except (ValueError, AttributeError):
                    # Invalid environment value, use default
                    pass
                    
    def _load_from_config_file(self):
        """Load preferences from local config file"""
        config_file = Path('.lambdalabs_config')
        if config_file.exists():
            try:
                import json
                with open(config_file, 'r') as f:
                    config_data = json.load(f)
                    
                # Apply config values
                for key, value in config_data.items():
                    if hasattr(self, key):
                        if key == 'verbosity_level':
                            self.verbosity_level = VerbosityLevel(value)
                        elif key == 'output_format':
                            self.output_format = OutputFormat(value)
                        else:
                            setattr(self, key, value)
                            
            except (json.JSONDecodeError, KeyError, ValueError):
                # Invalid config file, use defaults
                pass
                
    def save_config(self):
        """Save current preferences to config file"""
        config_data = {
            'verbosity_level': self.verbosity_level.value,
            'output_format': self.output_format.value,
            'show_timestamps': self.show_timestamps,
            'colored_output': self.colored_output,
            'show_progress_bars': self.show_progress_bars,
            'show_security_warnings': self.show_security_warnings,
            'show_cost_warnings': self.show_cost_warnings,
            'show_performance_metrics': self.show_performance_metrics,
            'max_table_rows': self.max_table_rows,
            'truncate_long_output': self.truncate_long_output,
            'save_to_file': self.save_to_file
        }
        
        try:
            import json
            config_file = Path('.lambdalabs_config')
            with open(config_file, 'w') as f:
                json.dump(config_data, f, indent=2)
        except Exception:
            # Config save failed, continue silently
            pass
            
    def should_show_debug(self) -> bool:
        """Check if debug info should be displayed"""
        return self.verbosity_level == VerbosityLevel.DEBUG
        
    def should_show_detailed(self) -> bool:
        """Check if detailed info should be displayed"""
        return self.verbosity_level in [VerbosityLevel.DETAILED, VerbosityLevel.DEBUG]
        
    def should_show_normal(self) -> bool:
        """Check if normal info should be displayed"""
        return self.verbosity_level in [VerbosityLevel.NORMAL, VerbosityLevel.DETAILED, VerbosityLevel.DEBUG]
        
    def should_show_minimal(self) -> bool:
        """Check if minimal info should always be displayed"""
        return True  # Minimal info always shown
        
    def get_table_limit(self) -> int:
        """Get maximum number of table rows to display"""
        if self.verbosity_level == VerbosityLevel.MINIMAL:
            return 10
        elif self.verbosity_level == VerbosityLevel.NORMAL:
            return 25
        elif self.verbosity_level == VerbosityLevel.DETAILED:
            return 50
        else:  # DEBUG
            return 100
            
    def format_output(self, message: str, level: str = "info") -> str:
        """Format output message based on current preferences"""
        if self.output_format == OutputFormat.JSON:
            import json
            from datetime import datetime
            
            output_data = {
                "timestamp": datetime.now().isoformat(),
                "level": level,
                "message": message
            }
            return json.dumps(output_data)
        elif self.output_format == OutputFormat.PLAIN:
            if self.show_timestamps:
                from datetime import datetime
                timestamp = datetime.now().strftime("%H:%M:%S")
                return f"[{timestamp}] {message}"
            return message
        else:  # RICH format
            return message  # Rich formatting handled by console


# Global preferences instance
_preferences = None


def get_preferences() -> OutputPreferences:
    """Get the global preferences instance"""
    global _preferences
    if _preferences is None:
        _preferences = OutputPreferences()
    return _preferences


def set_verbosity(level: VerbosityLevel):
    """Set global verbosity level"""
    prefs = get_preferences()
    prefs.verbosity_level = level
    prefs.save_config()


def set_output_format(format_type: OutputFormat):
    """Set global output format"""
    prefs = get_preferences()
    prefs.output_format = format_type
    prefs.save_config()


def toggle_colors():
    """Toggle colored output on/off"""
    prefs = get_preferences()
    prefs.colored_output = not prefs.colored_output
    prefs.save_config()
    return prefs.colored_output


def toggle_progress_bars():
    """Toggle progress bars on/off"""
    prefs = get_preferences()
    prefs.show_progress_bars = not prefs.show_progress_bars
    prefs.save_config()
    return prefs.show_progress_bars
