#!/usr/bin/env python3
"""
SSH Key Management Utilities for AWS Lambda Testing Toolkit
Handles dynamic SSH key generation and management for secure deployments
"""
import os
import subprocess
import tempfile
import boto3
from pathlib import Path
from datetime import datetime


class SSHKeyManager:
    """Manages SSH key creation, validation, and cleanup for the toolkit"""
    
    def __init__(self):
        self.ssh_dir = Path.home() / '.ssh'
        self.project_ssh_dir = Path.cwd() / '.ssh'
        self.key_name_prefix = 'lambda-testing-toolkit'
        
    def ensure_ssh_directories(self):
        """Create SSH directories if they don't exist"""
        self.ssh_dir.mkdir(mode=0o700, exist_ok=True)
        self.project_ssh_dir.mkdir(mode=0o700, exist_ok=True)
        
    def generate_key_pair(self, key_name=None):
        """
        Generate a new SSH key pair for the project
        Returns: (private_key_path, public_key_content, key_name)
        """
        if not key_name:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            key_name = f"{self.key_name_prefix}-{timestamp}"
            
        self.ensure_ssh_directories()
        
        # Generate key in project .ssh directory
        private_key_path = self.project_ssh_dir / f"{key_name}.pem"
        public_key_path = self.project_ssh_dir / f"{key_name}.pem.pub"
        
        # Generate SSH key pair
        try:
            subprocess.run([
                'ssh-keygen',
                '-t', 'rsa',
                '-b', '2048',
                '-f', str(private_key_path),
                '-N', '',  # No passphrase
                '-C', f'{key_name}@lambda-testing-toolkit'
            ], check=True, capture_output=True)
            
            # Set proper permissions
            private_key_path.chmod(0o600)
            public_key_path.chmod(0o644)
            
            # Read public key content - ensure file exists
            if not public_key_path.exists():
                raise FileNotFoundError(f"Public key file not created: {public_key_path}")
                
            with open(public_key_path, 'r') as f:
                public_key_content = f.read().strip()
                
            print(f"[SUCCESS] SSH key pair generated: {key_name}")
            print(f"[INFO] Private key: {private_key_path}")
            print(f"[INFO] Public key: {public_key_path}")
            
            return str(private_key_path), public_key_content, key_name
            
        except subprocess.CalledProcessError as e:
            raise Exception(f"Failed to generate SSH key: {e.stderr.decode()}")
            
    def find_existing_keys(self):
        """Find existing SSH keys for the project"""
        keys = []
        for key_file in self.project_ssh_dir.glob(f"{self.key_name_prefix}-*.pem"):
            if key_file.is_file():
                pub_file = Path(str(key_file) + '.pub')  # .pem.pub file
                if pub_file.exists():
                    with open(pub_file, 'r') as f:
                        pub_content = f.read().strip()
                    keys.append({
                        'name': key_file.stem,
                        'private_path': str(key_file),
                        'public_path': str(pub_file),
                        'public_content': pub_content
                    })
        return keys
        
    def list_user_keys(self):
        """List user's existing SSH keys"""
        user_keys = []
        for key_file in self.ssh_dir.glob("*.pem"):
            if key_file.is_file():
                user_keys.append(str(key_file))
        return user_keys
        
    def select_or_create_key(self):
        """
        Interactive key selection or creation
        Returns: (private_key_path, public_key_content, key_name)
        """
        print("\n" + "="*60)
        print("🔑 SSH KEY MANAGEMENT")
        print("="*60)
        
        # Check for existing project keys
        existing_keys = self.find_existing_keys()
        user_keys = self.list_user_keys()
        
        options = []
        if existing_keys:
            print("\n📁 Existing project SSH keys:")
            for i, key in enumerate(existing_keys, 1):
                print(f" [{i}] {key['name']}")
                options.append(('project', key))
                
        if user_keys:
            print(f"\n🏠 User SSH keys in {self.ssh_dir}:")
            start_idx = len(existing_keys) + 1
            for i, key_path in enumerate(user_keys, start_idx):
                key_name = Path(key_path).stem
                print(f" [{i}] {key_name}")
                options.append(('user', key_path))
                
        # Always offer to create new key
        create_idx = len(options) + 1
        print(f"\n🔑 Create new SSH key:")
        print(f" [{create_idx}] Generate new SSH key pair")
        
        while True:
            try:
                choice = int(input(f"\nSelect option (1-{create_idx}): "))
                
                if choice == create_idx:
                    # Create new key
                    return self.generate_key_pair()
                elif 1 <= choice <= len(options):
                    option_type, key_data = options[choice - 1]
                    
                    if option_type == 'project':
                        return (
                            key_data['private_path'],
                            key_data['public_content'],
                            key_data['name']
                        )
                    else:  # user key
                        # Need to get public key content
                        pub_path = Path(key_data).with_suffix('.pub')
                        if pub_path.exists():
                            with open(pub_path, 'r') as f:
                                pub_content = f.read().strip()
                            return str(key_data), pub_content, Path(key_data).stem
                        else:
                            from utils.enhanced_logging import get_logger
                            logger = get_logger(__name__)
                            logger.error(
                                f"Public key not found: {pub_path}",
                                suggestion="Ensure both .pem and .pub files exist for the selected SSH key"
                            )
                            continue
                else:
                    from utils.enhanced_logging import get_logger
                    logger = get_logger(__name__)
                    logger.error(
                        f"Invalid choice: {choice}",
                        suggestion=f"Please enter a number between 1 and {create_idx}"
                    )
                    
            except ValueError:
                from utils.enhanced_logging import get_logger
                logger = get_logger(__name__)
                logger.error(
                    "Invalid input - not a number",
                    suggestion="Please enter a valid number for your choice"
                )
                
    def cleanup_project_keys(self):
        """Remove all project-generated SSH keys"""
        keys = self.find_existing_keys()
        if not keys:
            print("[INFO] No project SSH keys found to cleanup")
            return
            
        print(f"[INFO] Found {len(keys)} project SSH keys to remove:")
        for key in keys:
            print(f"  - {key['name']}")
            
        confirm = input("\n⚠️  Remove all project SSH keys? (yes/no): ").strip().lower()
        if confirm == 'yes':
            for key in keys:
                try:
                    Path(key['private_path']).unlink()
                    Path(key['public_path']).unlink()
                    print(f"[SUCCESS] Removed: {key['name']}")
                except Exception as e:
                    from utils.enhanced_logging import get_logger
                    logger = get_logger(__name__)
                    logger.error(
                        f"Failed to remove SSH key {key['name']}: {str(e)}",
                        suggestion="Check file permissions and ensure the key files are not in use"
                    )
        else:
            print("[INFO] SSH key cleanup cancelled")


def create_aws_key_pair(ec2_client, key_name, public_key_content):
    """
    Create or update AWS EC2 Key Pair
    """
    try:
        # Check if key pair already exists
        try:
            existing = ec2_client.describe_key_pairs(KeyNames=[key_name])
            print(f"[WARNING] Key pair '{key_name}' already exists in AWS")
            
            # Delete existing key pair
            ec2_client.delete_key_pair(KeyName=key_name)
            print(f"[INFO] Deleted existing key pair: {key_name}")
            
        except ec2_client.exceptions.ClientError as e:
            if 'InvalidKeyPair.NotFound' not in str(e):
                raise
                
        # Import the public key
        response = ec2_client.import_key_pair(
            KeyName=key_name,
            PublicKeyMaterial=public_key_content
        )
        
        print(f"[SUCCESS] Created AWS key pair: {key_name}")
        return response['KeyPairId']
        
    except Exception as e:
        raise Exception(f"Failed to create AWS key pair: {str(e)}")


def validate_ssh_key(private_key_path):
    """Validate SSH private key file"""
    key_path = Path(private_key_path)
    
    if not key_path.exists():
        raise FileNotFoundError(f"SSH key not found: {private_key_path}")
        
    if not key_path.is_file():
        raise ValueError(f"SSH key path is not a file: {private_key_path}")
        
    # Check permissions
    stat = key_path.stat()
    if stat.st_mode & 0o077:  # Check if group/others have any permissions
        print(f"[WARNING] SSH key has overly permissive permissions: {oct(stat.st_mode)}")
        key_path.chmod(0o600)
        print(f"[INFO] Fixed SSH key permissions: {private_key_path}")
        
    # Basic validation - check if it looks like a private key
    with open(private_key_path, 'r') as f:
        content = f.read()
        if not ('BEGIN PRIVATE KEY' in content or 'BEGIN RSA PRIVATE KEY' in content):
            raise ValueError(f"File does not appear to be a valid SSH private key: {private_key_path}")
            
    return True


if __name__ == "__main__":
    # Test the SSH key manager
    manager = SSHKeyManager()
    
    print("Testing SSH Key Manager...")
    try:
        private_key, public_key, key_name = manager.select_or_create_key()
        print(f"\nSelected/Created key: {key_name}")
        print(f"Private key: {private_key}")
        print(f"Public key length: {len(public_key)} characters")
        
        # Validate the key
        validate_ssh_key(private_key)
        print("[SUCCESS] SSH key validation passed")
        
    except Exception as e:
        print(f"[ERROR] {e}")
