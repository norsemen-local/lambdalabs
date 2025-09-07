#!/usr/bin/env python3
"""
Fresh launcher for lambdalabs to avoid cached imports
"""
import sys
import os
import importlib

def main():
    # Clear any cached modules
    if 'lambdalabs' in sys.modules:
        del sys.modules['lambdalabs']
    
    # Clear __pycache__ directories
    os.system("find . -name '__pycache__' -exec rm -rf {} + 2>/dev/null || true")
    os.system("find . -name '*.pyc' -delete 2>/dev/null || true")
    
    # Fresh import and run
    import lambdalabs
    importlib.reload(lambdalabs)
    
    # Run the main function
    lambdalabs.main()

if __name__ == "__main__":
    main()
