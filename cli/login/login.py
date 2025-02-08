import os
import getpass
import boto3
import jwt
from datetime import datetime, timedelta
from botocore.exceptions import ClientError

# Configuration for JWT storage
JWT_SECRET = "hackathon_secret_key"  # For demonstration only; use a secure secret in real scenarios
JWT_ALGORITHM = "HS256"
JWT_FILE = "aws_login.jwt"
JWT_EXP_DELTA_SECONDS = 3600  # Token validity (e.g., 1 hour)

def get_stored_credentials():
    """
    Checks if a JWT file exists and returns its payload (AWS credentials)
    if the token is valid (i.e., not expired).
    """
    print("Checking for stored AWS credentials...")
    if os.path.exists(JWT_FILE):
        with open(JWT_FILE, "r") as f:
            token = f.read().strip()
            try:
                payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
                return payload
            except jwt.ExpiredSignatureError:
                print("Stored credentials have expired.")
            except jwt.InvalidTokenError:
                print("Invalid token found.")
    return None

def store_credentials(access_key: str, secret_key: str, region: str):
    """
    Creates a JWT containing AWS credentials and writes it to a file.
    """
    payload = {
        "access_key": access_key,
        "secret_key": secret_key,
        "region": region,
        "exp": datetime.utcnow() + timedelta(seconds=JWT_EXP_DELTA_SECONDS)
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    with open(JWT_FILE, "w") as f:
        # jwt.encode returns a string in PyJWT>=2.0 by default.
        f.write(token)
        print("Credentials stored securely.")


def login_to_aws():
    """
    Attempts to log in to AWS by first checking for stored credentials in a JWT.
    If none are available or they have expired, prompts the user for credentials.
    Then verifies the credentials using the STS GetCallerIdentity API.
    Returns a boto3 Session if successful, or None otherwise.
    """
    creds = get_stored_credentials()
    if creds:
        print("\nUsing stored AWS credentials from JWT...")
        access_key = creds["access_key"]
        secret_key = creds["secret_key"]
        region = creds["region"]
    else:
        print("\n=== AWS Login ===")
        access_key = input("Enter AWS Access Key ID: ").strip()
        secret_key = getpass.getpass("Enter AWS Secret Access Key: ")
        region = input("Enter AWS Region (default us-east-1): ").strip() or "us-east-1"

    try:
        session = boto3.Session(
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            region_name=region
        )
        sts_client = session.client("sts")
        identity = sts_client.get_caller_identity()
        
        print("\nLogin successful!")
        print(f"Account: {identity.get('Account')}")
        print(f"UserId: {identity.get('UserId')}")
        print(f"ARN: {identity.get('Arn')}")
        
        # If we just got credentials from user input, store them in JWT.
        
        store_credentials(access_key, secret_key, region)
        return session
    except ClientError as e:
        print("\nInvalid credentials. Please try again.")
        return None
    except Exception as e:
        print(f"\nLogin failed: {str(e)}")
        return None

if __name__ == "__main__":
    session = login_to_aws()
    if session:
        print("AWS session is ready!")
    else:
        print("AWS login failed.")
