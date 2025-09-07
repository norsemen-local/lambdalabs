#!/usr/bin/env python3
"""
Safety Utilities for AWS Lambda Testing Toolkit
Simple confirmation prompts and disclaimers - user is responsible for deployment location
"""
import os
import json
from datetime import datetime
from pathlib import Path


class SafetyManager:
    """Simple safety manager with basic confirmation prompts"""
    
    def __init__(self):
        self.dry_run_mode = False
        
    def enable_dry_run(self):
        """Enable dry-run mode (no actual AWS operations)"""
        self.dry_run_mode = True
        print("[INFO] 🧪 DRY-RUN MODE ENABLED - No AWS resources will be created")
        
    def disable_dry_run(self):
        """Disable dry-run mode"""
        self.dry_run_mode = False
        print("[INFO] ✅ DRY-RUN MODE DISABLED - AWS operations will be executed")
        
    def is_dry_run(self):
        """Check if currently in dry-run mode"""
        return self.dry_run_mode
        
    def show_security_disclaimer(self):
        """Display security disclaimers before deployment"""
        print("\n" + "="*70)
        print("🚨 SECURITY DISCLAIMER - READ CAREFULLY")
        print("="*70)
        print("⚠️  This toolkit creates INTENTIONALLY VULNERABLE infrastructure")
        print("⚠️  Use ONLY in dedicated testing/lab environments")
        print("⚠️  NEVER deploy in production or shared AWS accounts")
        print("⚠️  Resources will incur AWS charges - clean up when finished")
        print("⚠️  You are responsible for appropriate use and deployment")
        print("="*70)
        print()
        
    def get_user_confirmation(self, operation_name, details=None):
        """Get user confirmation for operations"""
        print(f"\n🚨 CONFIRMATION REQUIRED: {operation_name}")
        
        if details:
            print("Details:")
            if isinstance(details, list):
                for detail in details:
                    print(f"  - {detail}")
            else:
                print(f"  {details}")
                
        print("\n⚠️  This operation will create AWS resources that incur costs.")
        print("💡 Remember to clean up resources when testing is complete.")
        
        while True:
            response = input(f"\nProceed with {operation_name}? (yes/no): ").strip().lower()
            
            if response in ['yes', 'y']:
                print(f"[INFO] ✅ User confirmed: {operation_name}")
                return True
            elif response in ['no', 'n']:
                print(f"[INFO] ❌ User cancelled: {operation_name}")
                return False
            else:
                print("[ERROR] Please answer 'yes' or 'no'")
                
    def validate_operation_safety(self, operation_name, **kwargs):
        """Simple operation validation - mainly for dry-run mode"""
        if self.dry_run_mode:
            print(f"\n[DRY-RUN] Would execute: {operation_name}")
            if kwargs:
                print(f"[DRY-RUN] Parameters: {json.dumps(kwargs, indent=2)}")
            return True, False  # Safe but don't proceed
            
        return True, True  # Proceed with operation
        
    def create_deployment_record(self, stack_name, details=None):
        """Create a simple record of deployment for tracking"""
        record_file = Path.cwd() / f"deployment_{stack_name}.json"
        
        record_data = {
            "stack_name": stack_name,
            "deployment_time": datetime.utcnow().isoformat(),
            "details": details or {}
        }
        
        try:
            with open(record_file, 'w') as f:
                json.dump(record_data, f, indent=2)
                
            print(f"[INFO] 📝 Created deployment record: {record_file.name}")
            
        except Exception as e:
            print(f"[WARNING] Could not create deployment record: {e}")
            
    def remove_deployment_record(self, stack_name):
        """Remove deployment record"""
        record_file = Path.cwd() / f"deployment_{stack_name}.json"
        
        try:
            if record_file.exists():
                record_file.unlink()
                print(f"[INFO] 🗑️ Removed deployment record: {record_file.name}")
        except Exception as e:
            print(f"[WARNING] Could not remove deployment record: {e}")


def main():
    """Simple command-line interface"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Simple safety utilities")
    parser.add_argument("--dry-run", action="store_true", help="Enable dry-run mode")
    parser.add_argument("--disclaimer", action="store_true", help="Show security disclaimer")
    
    args = parser.parse_args()
    
    safety = SafetyManager()
    
    if args.dry_run:
        safety.enable_dry_run()
        
    if args.disclaimer:
        safety.show_security_disclaimer()


if __name__ == "__main__":
    main()
