import boto3
import json
import os

# Initialize AWS clients
sts_client = boto3.client("sts")
iam_client = boto3.client("iam")
s3_client = boto3.client("s3")
ec2_client = boto3.client("ec2")

def lambda_handler(event, context):
    """
    Lambda function that performs AWS security-related actions based on user input.
    """
    try:
        # Parse input parameters
        action = event.get("action", "sts_get_identity").lower()
        instance_name = event.get("instance_name", "DockerInstance")
        docker_image = event.get("docker_image", "nginx")
        instance_type = event.get("instance_type", "t2.micro")
        key_name = event.get("key_name", "dev-team-key-pair")

        if action == "sts_get_identity":
            return get_caller_identity()

        elif action == "sts_get_session_token":
            return get_session_token()

        elif action == "list_roles":
            return list_iam_roles()

        elif action == "list_users":
            return list_iam_users()

        elif action == "list_s3_buckets":
            return list_s3_buckets()

        elif action == "list_s3_objects":
            bucket_name = event.get("bucket_name")
            if bucket_name:
                return list_s3_objects(bucket_name)
            return response_template(400, "Missing 'bucket_name' parameter.")

        elif action == "s3_enum":
            return s3_enum()  # Full S3 enumeration

        elif action == "list_ec2_instances":
            return list_ec2_instances()

        else:
            return response_template(400, f"Invalid action: {action}")

    except Exception as e:
        return response_template(500, f"Error occurred: {str(e)}")

# -------------------- STS (AWS Identity) --------------------
def get_caller_identity():
    """ Returns the AWS identity executing the function. """
    try:
        identity = sts_client.get_caller_identity()
        return response_template(200, identity)
    except Exception as e:
        return response_template(500, f"Failed to retrieve identity: {str(e)}")

def get_session_token():
    """ Returns temporary AWS session token. """
    try:
        token = sts_client.get_session_token()
        return response_template(200, token["Credentials"])
    except Exception as e:
        return response_template(500, f"Failed to retrieve session token: {str(e)}")

# -------------------- IAM (User & Role Enumeration) --------------------
def list_iam_roles():
    """ Lists IAM roles in the AWS account. """
    try:
        roles = iam_client.list_roles()
        role_names = [role["RoleName"] for role in roles["Roles"]]
        return response_template(200, role_names)
    except Exception as e:
        return response_template(500, f"Failed to list IAM roles: {str(e)}")

def list_iam_users():
    """ Lists IAM users in the AWS account. """
    try:
        users = iam_client.list_users()
        user_names = [user["UserName"] for user in users["Users"]]
        return response_template(200, user_names)
    except Exception as e:
        return response_template(500, f"Failed to list IAM users: {str(e)}")

# -------------------- S3 (Bucket & Object Enumeration) --------------------
def list_s3_buckets():
    """ Lists all S3 buckets accessible by the Lambda function. """
    try:
        buckets_response = s3_client.list_buckets()
        bucket_names = [bucket["Name"] for bucket in buckets_response.get("Buckets", [])]

        if not bucket_names:
            return response_template(200, "No S3 buckets found.")

        return response_template(200, bucket_names)

    except Exception as e:
        return response_template(500, f"Failed to list S3 buckets: {str(e)}")

def list_s3_objects(bucket_name):
    """ Lists objects in a given S3 bucket. """
    try:
        objects_response = s3_client.list_objects_v2(Bucket=bucket_name)
        object_names = [obj["Key"] for obj in objects_response.get("Contents", [])]

        if not object_names:
            return response_template(200, f"No objects found in bucket '{bucket_name}'.")

        return response_template(200, object_names)

    except Exception as e:
        return response_template(500, f"Failed to list objects in bucket '{bucket_name}': {str(e)}")

def s3_enum():
    """ Enumerates all S3 buckets and lists their objects, saving the output to a report file. """
    try:
        print("[INFO] Enumerating S3 Buckets...")
        buckets_response = s3_client.list_buckets()
        bucket_names = [bucket["Name"] for bucket in buckets_response.get("Buckets", [])]

        if not bucket_names:
            return response_template(200, "No S3 buckets found.")

        bucket_results = {}

        for bucket_name in bucket_names:
            try:
                print(f"[INFO] Enumerating objects in bucket: {bucket_name}")
                objects_response = s3_client.list_objects_v2(Bucket=bucket_name)
                object_names = [obj["Key"] for obj in objects_response.get("Contents", [])]
                bucket_results[bucket_name] = object_names if object_names else "No objects found"
            except Exception as e:
                print(f"[ERROR] Failed to retrieve objects from {bucket_name}: {str(e)}")
                bucket_results[bucket_name] = f"Error retrieving objects: {str(e)}"

        # Save report
        report_filename = "/tmp/s3_enum_report.json"
        with open(report_filename, "w") as report_file:
            json.dump(bucket_results, report_file, indent=4)

        print(f"[SUCCESS] S3 Enumeration report saved to {report_filename}")

        return response_template(200, {"message": "S3 Enumeration completed", "report_file": report_filename})

    except Exception as e:
        return response_template(500, f"Failed to enumerate S3: {str(e)}")

# -------------------- EC2 (Instance Management) --------------------
def list_ec2_instances():
    """ Lists all EC2 instances with their state and public DNS. """
    try:
        instances = ec2_client.describe_instances()
        instance_list = []

        for reservation in instances["Reservations"]:
            for instance in reservation["Instances"]:
                instance_list.append({
                    "InstanceId": instance["InstanceId"],
                    "State": instance["State"]["Name"],
                    "PublicDnsName": instance.get("PublicDnsName", "N/A"),
                    "InstanceType": instance["InstanceType"],
                    "LaunchTime": str(instance["LaunchTime"])
                })

        return response_template(200, instance_list)

    except Exception as e:
        return response_template(500, f"Failed to list EC2 instances: {str(e)}")

# -------------------- Response Formatting --------------------
def response_template(status_code, data):
    """ Standardized JSON response format """
    return {
        "statusCode": status_code,
        "body": json.dumps(data, indent=2)
    }
