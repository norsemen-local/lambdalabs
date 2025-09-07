#!/usr/bin/env python3
"""
Network Security Management for AWS Lambda Testing Toolkit
Handles dynamic IP detection and security group updates with fallbacks
"""
import boto3
import requests
import logging
import time
import socket
from typing import Optional, List, Dict, Tuple
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)

class IPDetector:
    """Handles IP detection with multiple fallback services"""
    
    def __init__(self):
        # Multiple IP detection services for reliability
        self.services = [
            {
                'name': 'ipify',
                'url': 'https://api.ipify.org',
                'timeout': 5
            },
            {
                'name': 'AWS CheckIP',
                'url': 'https://checkip.amazonaws.com',
                'timeout': 5
            },
            {
                'name': 'ipinfo',
                'url': 'https://ipinfo.io/ip',
                'timeout': 5
            },
            {
                'name': 'icanhazip',
                'url': 'https://icanhazip.com',
                'timeout': 5
            }
        ]
        self.current_ip = None
        
    def get_current_ip(self, verbose: bool = True) -> Optional[str]:
        """
        Get current public IP using multiple fallback services
        
        Args:
            verbose: Whether to print status messages
            
        Returns:
            str: Current public IP address or None if all services fail
        """
        if verbose:
            print("🌐 Detecting your public IP address...")
            
        for service in self.services:
            try:
                if verbose:
                    print(f"   Trying {service['name']}...", end=" ")
                    
                response = requests.get(
                    service['url'], 
                    timeout=service['timeout'],
                    headers={'User-Agent': 'LambdaLabs-Toolkit/1.0'}
                )
                
                if response.status_code == 200:
                    ip = response.text.strip()
                    
                    # Validate IP format
                    if self._is_valid_ip(ip):
                        if verbose:
                            print(f"✅ {ip}")
                        self.current_ip = ip
                        return ip
                    else:
                        if verbose:
                            print(f"❌ Invalid format: {ip}")
                        continue
                else:
                    if verbose:
                        print(f"❌ HTTP {response.status_code}")
                    continue
                    
            except requests.RequestException as e:
                if verbose:
                    print(f"❌ {str(e)[:50]}...")
                continue
            except Exception as e:
                if verbose:
                    print(f"❌ Error: {str(e)[:30]}...")
                continue
                
        # All services failed
        if verbose:
            print("❌ All IP detection services failed")
            print("💡 You can specify IP manually with: --ip YOUR.IP.ADDRESS")
            
        return None
    
    def _is_valid_ip(self, ip: str) -> bool:
        """Validate IP address format"""
        try:
            parts = ip.split('.')
            if len(parts) != 4:
                return False
            for part in parts:
                num = int(part)
                if num < 0 or num > 255:
                    return False
            return True
        except (ValueError, AttributeError):
            return False
    
    def verify_ip_access(self, ip: str, target_host: str, target_port: int = 22, timeout: int = 5) -> bool:
        """
        Verify if the given IP can actually reach the target
        
        Args:
            ip: IP address to test from (informational)
            target_host: Target hostname/IP to test connectivity to
            target_port: Target port (default: SSH port 22)
            timeout: Connection timeout in seconds
            
        Returns:
            bool: True if connection succeeds, False otherwise
        """
        try:
            # Simple socket connection test
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            
            result = sock.connect_ex((target_host, target_port))
            sock.close()
            
            # Connection successful if result is 0
            return result == 0
            
        except Exception as e:
            logger.debug(f"Connection test failed: {e}")
            return False


class SecurityGroupManager:
    """Manages AWS Security Group IP rules for dynamic access control"""
    
    def __init__(self, session: boto3.Session):
        self.session = session
        self.ec2 = session.client('ec2')
        
    def get_current_ip_rules(self, sg_id: str, ports: List[int] = [22, 8080, 5005]) -> Dict[int, List[str]]:
        """
        Get current IP rules for specified ports in a security group
        
        Args:
            sg_id: Security group ID
            ports: List of ports to check (default: SSH, HTTP alt, debug)
            
        Returns:
            Dict mapping port to list of allowed CIDR blocks
        """
        try:
            response = self.ec2.describe_security_groups(GroupIds=[sg_id])
            sg = response['SecurityGroups'][0]
            
            port_rules = {}
            
            for port in ports:
                port_rules[port] = []
                
                for rule in sg.get('IpPermissions', []):
                    # Check if this rule applies to our port
                    if (rule.get('FromPort') == port and rule.get('ToPort') == port and 
                        rule.get('IpProtocol') == 'tcp'):
                        
                        # Extract CIDR blocks
                        for ip_range in rule.get('IpRanges', []):
                            cidr = ip_range.get('CidrIp')
                            if cidr:
                                port_rules[port].append(cidr)
                                
            return port_rules
            
        except Exception as e:
            logger.error(f"Failed to get security group rules: {e}")
            return {}
    
    def update_ip_access(self, sg_id: str, old_ip: str, new_ip: str, ports: List[int] = [22, 8080, 5005]) -> bool:
        """
        Replace old IP with new IP in security group rules
        
        Args:
            sg_id: Security group ID
            old_ip: IP to remove (can be None to just add)
            new_ip: IP to add
            ports: List of ports to update
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            success = True
            
            # Remove old IP rules if specified
            if old_ip:
                print(f"🔄 Removing old IP access: {old_ip}")
                if not self._remove_ip_rules(sg_id, old_ip, ports):
                    print(f"⚠️  Warning: Could not remove old IP {old_ip}")
                    success = False
            
            # Add new IP rules
            print(f"🔄 Adding new IP access: {new_ip}")
            if not self._add_ip_rules(sg_id, new_ip, ports):
                print(f"❌ Failed to add new IP {new_ip}")
                return False
                
            if success:
                print(f"✅ IP access updated successfully: {old_ip or 'none'} → {new_ip}")
            
            return success
            
        except Exception as e:
            logger.error(f"Failed to update IP access: {e}")
            print(f"❌ Failed to update IP access: {e}")
            return False
    
    def add_ip_access(self, sg_id: str, new_ip: str, ports: List[int] = [22, 8080, 5005]) -> bool:
        """
        Add new IP access without removing existing IPs (multi-user support)
        
        Args:
            sg_id: Security group ID
            new_ip: IP to add
            ports: List of ports to grant access to
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            # Check if IP already has access
            current_rules = self.get_current_ip_rules(sg_id, ports)
            new_ip_cidr = f"{new_ip}/32"
            
            already_has_access = []
            needs_access = []
            
            for port in ports:
                if new_ip_cidr in current_rules.get(port, []):
                    already_has_access.append(port)
                else:
                    needs_access.append(port)
            
            if already_has_access:
                print(f"ℹ️  IP {new_ip} already has access to port(s): {already_has_access}")
            
            if needs_access:
                print(f"🔄 Adding IP {new_ip} access to port(s): {needs_access}")
                if self._add_ip_rules(sg_id, new_ip, needs_access):
                    print(f"✅ Added IP access for {new_ip}")
                    return True
                else:
                    print(f"❌ Failed to add IP access for {new_ip}")
                    return False
            else:
                print(f"✅ IP {new_ip} already has complete access")
                return True
                
        except Exception as e:
            logger.error(f"Failed to add IP access: {e}")
            print(f"❌ Failed to add IP access: {e}")
            return False
    
    def _remove_ip_rules(self, sg_id: str, ip: str, ports: List[int]) -> bool:
        """Remove IP rules from security group"""
        try:
            ip_permissions = []
            for port in ports:
                ip_permissions.append({
                    'IpProtocol': 'tcp',
                    'FromPort': port,
                    'ToPort': port,
                    'IpRanges': [{'CidrIp': f"{ip}/32"}]
                })
            
            self.ec2.revoke_security_group_ingress(
                GroupId=sg_id,
                IpPermissions=ip_permissions
            )
            return True
            
        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == 'InvalidPermission.NotFound':
                # Rule doesn't exist, which is fine
                return True
            else:
                logger.warning(f"Could not remove rules for {ip}: {e}")
                return False
        except Exception as e:
            logger.warning(f"Could not remove rules for {ip}: {e}")
            return False
    
    def _add_ip_rules(self, sg_id: str, ip: str, ports: List[int]) -> bool:
        """Add IP rules to security group"""
        try:
            ip_permissions = []
            for port in ports:
                ip_permissions.append({
                    'IpProtocol': 'tcp',
                    'FromPort': port,
                    'ToPort': port,
                    'IpRanges': [{'CidrIp': f"{ip}/32", 'Description': f"LambdaLabs access from {ip}"}]
                })
            
            self.ec2.authorize_security_group_ingress(
                GroupId=sg_id,
                IpPermissions=ip_permissions
            )
            return True
            
        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == 'InvalidPermission.Duplicate':
                # Rule already exists, which is fine
                return True
            else:
                logger.error(f"Could not add rules for {ip}: {e}")
                return False
        except Exception as e:
            logger.error(f"Could not add rules for {ip}: {e}")
            return False
    
    def get_security_group_status(self, sg_id: str) -> Dict:
        """Get comprehensive status of security group configuration"""
        try:
            response = self.ec2.describe_security_groups(GroupIds=[sg_id])
            sg = response['SecurityGroups'][0]
            
            status = {
                'security_group_id': sg_id,
                'group_name': sg.get('GroupName', 'Unknown'),
                'vpc_id': sg.get('VpcId'),
                'current_rules': [],
                'ports_summary': {}
            }
            
            # Analyze rules
            common_ports = [22, 80, 8080, 443, 5005]
            
            for rule in sg.get('IpPermissions', []):
                from_port = rule.get('FromPort')
                to_port = rule.get('ToPort')
                protocol = rule.get('IpProtocol')
                
                for ip_range in rule.get('IpRanges', []):
                    cidr = ip_range.get('CidrIp')
                    description = ip_range.get('Description', '')
                    
                    rule_info = {
                        'protocol': protocol,
                        'from_port': from_port,
                        'to_port': to_port,
                        'cidr': cidr,
                        'description': description
                    }
                    status['current_rules'].append(rule_info)
                    
                    # Track common ports
                    if from_port in common_ports:
                        if from_port not in status['ports_summary']:
                            status['ports_summary'][from_port] = []
                        status['ports_summary'][from_port].append(cidr)
            
            return status
            
        except Exception as e:
            logger.error(f"Failed to get security group status: {e}")
            return {'error': str(e)}


class NetworkSecurityManager:
    """Main class combining IP detection and security group management"""
    
    def __init__(self, session: boto3.Session):
        self.session = session
        self.ip_detector = IPDetector()
        self.sg_manager = SecurityGroupManager(session)
        
    def get_current_ip_with_fallbacks(self, verbose: bool = True) -> Optional[str]:
        """Get current IP with enhanced error handling and user guidance"""
        return self.ip_detector.get_current_ip(verbose=verbose)
    
    def check_ip_access_status(self, deployment_data: Dict) -> Dict:
        """
        Check current IP access status for a deployment
        
        Args:
            deployment_data: Deployment information containing security group details
            
        Returns:
            Dict with access status information
        """
        try:
            # Get current IP
            current_ip = self.ip_detector.get_current_ip(verbose=False)
            if not current_ip:
                return {
                    'status': 'error',
                    'message': 'Could not detect current IP address',
                    'current_ip': None,
                    'can_proceed': False
                }
            
            # Find security group ID from deployment data
            sg_id = self._extract_security_group_id(deployment_data)
            if not sg_id:
                return {
                    'status': 'error',
                    'message': 'Could not find security group in deployment data',
                    'current_ip': current_ip,
                    'can_proceed': False
                }
            
            # Get current security group rules
            current_rules = self.sg_manager.get_current_ip_rules(sg_id)
            current_ip_cidr = f"{current_ip}/32"
            
            # Check if current IP has access
            has_access = {}
            for port, cidrs in current_rules.items():
                has_access[port] = current_ip_cidr in cidrs
            
            all_access = all(has_access.values())
            
            # Try to get EC2 public DNS for connectivity test
            ec2_dns = self._extract_ec2_public_dns(deployment_data)
            connectivity_test = None
            
            if ec2_dns and all_access:
                connectivity_test = self.ip_detector.verify_ip_access(
                    current_ip, ec2_dns, 22, timeout=3
                )
            
            return {
                'status': 'success',
                'current_ip': current_ip,
                'security_group_id': sg_id,
                'has_access': has_access,
                'all_ports_accessible': all_access,
                'current_rules': current_rules,
                'connectivity_test': connectivity_test,
                'ec2_public_dns': ec2_dns,
                'can_proceed': all_access
            }
            
        except Exception as e:
            logger.error(f"Failed to check IP access status: {e}")
            return {
                'status': 'error',
                'message': str(e),
                'can_proceed': False
            }
    
    def update_deployment_ip_access(self, deployment_data: Dict, new_ip: Optional[str] = None) -> bool:
        """
        Update IP access for an existing deployment
        
        Args:
            deployment_data: Deployment information
            new_ip: Specific IP to use (if None, will auto-detect)
            
        Returns:
            bool: True if successful
        """
        try:
            # Get target IP
            if new_ip:
                if not self.ip_detector._is_valid_ip(new_ip):
                    print(f"❌ Invalid IP address format: {new_ip}")
                    return False
                target_ip = new_ip
                print(f"🎯 Using specified IP: {target_ip}")
            else:
                target_ip = self.ip_detector.get_current_ip(verbose=True)
                if not target_ip:
                    return False
            
            # Get security group ID
            sg_id = self._extract_security_group_id(deployment_data)
            if not sg_id:
                print("❌ Could not find security group in deployment data")
                return False
            
            print(f"🔍 Found security group: {sg_id}")
            
            # Get current rules to see what needs updating
            current_rules = self.sg_manager.get_current_ip_rules(sg_id)
            target_ip_cidr = f"{target_ip}/32"
            
            # Find existing lambdalabs IPs that need to be replaced
            existing_lambdalabs_ips = set()
            for port, cidrs in current_rules.items():
                for cidr in cidrs:
                    if cidr.endswith('/32'):  # Single IP rules
                        existing_lambdalabs_ips.add(cidr[:-3])  # Remove /32 suffix
            
            # Remove lambdalabs-specific IPs and add new one
            ports = [22, 8080, 5005]  # Standard lambdalabs ports
            
            if existing_lambdalabs_ips:
                print(f"🔄 Found existing access IPs: {list(existing_lambdalabs_ips)}")
                # For simplicity, replace the first existing IP
                old_ip = list(existing_lambdalabs_ips)[0]
                return self.sg_manager.update_ip_access(sg_id, old_ip, target_ip, ports)
            else:
                print(f"🔄 No existing IP rules found, adding new access")
                return self.sg_manager.add_ip_access(sg_id, target_ip, ports)
                
        except Exception as e:
            logger.error(f"Failed to update deployment IP access: {e}")
            print(f"❌ Failed to update IP access: {e}")
            return False
    
    def add_team_member_access(self, deployment_data: Dict, new_ip: str) -> bool:
        """Add access for additional team member without removing existing access"""
        try:
            if not self.ip_detector._is_valid_ip(new_ip):
                print(f"❌ Invalid IP address format: {new_ip}")
                return False
            
            sg_id = self._extract_security_group_id(deployment_data)
            if not sg_id:
                print("❌ Could not find security group in deployment data")
                return False
            
            print(f"🔍 Adding team member access to security group: {sg_id}")
            return self.sg_manager.add_ip_access(sg_id, new_ip, [22, 8080, 5005])
            
        except Exception as e:
            logger.error(f"Failed to add team member access: {e}")
            print(f"❌ Failed to add team member access: {e}")
            return False
    
    def _extract_security_group_id(self, deployment_data: Dict) -> Optional[str]:
        """Extract security group ID from deployment data"""
        try:
            resources = deployment_data.get("Resources", [])
            for resource in resources:
                if resource.get("ResourceType") == "AWS::EC2::SecurityGroup":
                    return resource.get("PhysicalResourceId")
            return None
        except Exception as e:
            logger.error(f"Failed to extract security group ID: {e}")
            return None
    
    def _extract_ec2_public_dns(self, deployment_data: Dict) -> Optional[str]:
        """Extract EC2 public DNS from deployment data"""
        try:
            arns = deployment_data.get("ARNs", {})
            for logical_id, arn_info in arns.items():
                if isinstance(arn_info, dict) and "PublicDNS" in arn_info:
                    public_dns = arn_info["PublicDNS"]
                    if public_dns and public_dns != "N/A":
                        return public_dns
            return None
        except Exception as e:
            logger.error(f"Failed to extract EC2 public DNS: {e}")
            return None
