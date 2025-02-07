from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import List, Dict, Set, Optional, Union, Any
from enum import Enum
import boto3
from botocore.exceptions import ClientError, NoCredentialsError, PartialCredentialsError
import logging
from datetime import datetime
from moto import mock_aws



# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('CloudScanner')

class CloudProvider(Enum):
    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"
    
class ResourceType(Enum):
    COMPUTE = "compute"  # EC2, Azure VM, GCP Compute
    SERVERLESS = "serverless"  # Lambda, Functions, Cloud Functions
    DATABASE = "database"  # RDS, CosmosDB, Cloud SQL
    STORAGE = "storage"  # S3, Blob Storage, Cloud Storage
    QUEUE = "queue"  # SQS, Service Bus, Cloud Pub/Sub
    NETWORK = "network"  # VPC, VNET, VPC
    CONTAINER = "container"  # ECS/EKS, AKS, GKE
    CACHE = "cache"  # ElastiCache, Redis Cache, Memorystore
    API = "api"  # API Gateway, API Management, Cloud Endpoints

@dataclass
class CloudResource:
    id: str
    name: str
    provider: CloudProvider
    type: ResourceType
    region: str
    properties: Dict
    dependencies: Set[str] = None
    tags: Dict = None
    created_at: Optional[datetime] = None
    last_modified: Optional[datetime] = None
    
    def __post_init__(self):
        self.dependencies = self.dependencies or set()
        self.tags = self.tags or {}

class CloudScanner(ABC):
    """Base class for cloud provider scanners"""
    
    @abstractmethod
    def authenticate(self) -> bool:
        """Authenticate with the cloud provider"""
        pass
    
    @abstractmethod
    def scan_resources(self) -> List[CloudResource]:
        """Scan all resources in the cloud provider"""
        pass
    
    @abstractmethod
    def get_dependencies(self, resource: CloudResource) -> Set[str]:
        """Get dependencies for a specific resource"""
        pass

class AWSScanner(CloudScanner):
    def __init__(self, region: str, profile: str = None):
        self.region = region
        self.profile = profile
        try:
            # Initialize AWS session
            self.session = boto3.Session(profile_name=profile, region_name=region)
            self._initialize_clients()
            logger.info(f"Initialized AWS Scanner for region {region}")
        except (NoCredentialsError, PartialCredentialsError) as e:
            logger.error(f"AWS credentials not found or incomplete: {str(e)}")
            raise
        except Exception as e:
            logger.error(f"Failed to initialize AWS scanner: {str(e)}")
            raise

    def _initialize_clients(self):
        """Initialize all AWS service clients"""
        try:
            self.lambda_client = self.session.client('lambda')
            self.ec2_client = self.session.client('ec2')
            self.rds_client = self.session.client('rds')
            self.s3_client = self.session.client('s3')
            self.sqs_client = self.session.client('sqs')
            self.ecs_client = self.session.client('ecs')
            self.eks_client = self.session.client('eks')
            self.elasticache_client = self.session.client('elasticache')
            self.apigateway_client = self.session.client('apigateway')
        except Exception as e:
            logger.error(f"Failed to initialize AWS clients: {str(e)}")
            raise
    

    def authenticate(self) -> bool:
        """Verify AWS authentication"""
        try:
            sts_client = self.session.client('sts')
            sts_client.get_caller_identity()
            logger.info("AWS authentication successful")
            return True
        except (NoCredentialsError, PartialCredentialsError) as e:
            logger.error(f"AWS credentials not found or incomplete: {str(e)}")
            return False
        except Exception as e:
            logger.error(f"AWS authentication failed: {str(e)}")
            return False

    def scan_resources(self) -> List[CloudResource]:
        """Scan all AWS resources"""
        resources = []
        scan_methods = [
            self._scan_ec2_instances,
            self._scan_lambda_functions,
            self._scan_rds_instances,
            self._scan_s3_buckets,
            self._scan_sqs_queues
        ]
        
        for scan_method in scan_methods:
            try:
                logger.info(f"Starting {scan_method.__name__}")
                method_resources = scan_method()
                resources.extend(method_resources)
                logger.info(f"Completed {scan_method.__name__}, found {len(method_resources)} resources")
            except Exception as e:
                logger.error(f"Error in {scan_method.__name__}: {str(e)}")
                continue
        
        return resources
    
    def _scan_ec2_instances(self) -> List[CloudResource]:
        """Scan EC2 instances"""
        resources = []
        try:
            paginator = self.ec2_client.get_paginator('describe_instances')
            for page in paginator.paginate():
                for reservation in page['Reservations']:
                    for instance in reservation['Instances']:
                        resources.append(CloudResource(
                            id=instance['InstanceId'],
                            name=self._get_name_from_tags(instance.get('Tags', [])),
                            provider=CloudProvider.AWS,
                            type=ResourceType.COMPUTE,
                            region=self.region,
                            properties={
                                'instance_type': instance['InstanceType'],
                                'state': instance['State']['Name'],
                                'vpc_id': instance.get('VpcId'),
                                'private_ip': instance.get('PrivateIpAddress'),
                                'public_ip': instance.get('PublicIpAddress'),
                                'platform': instance.get('Platform'),
                                'architecture': instance.get('Architecture'),
                                'launch_time': instance.get('LaunchTime').isoformat() if instance.get('LaunchTime') else None
                            },
                            tags=self._convert_tags(instance.get('Tags', [])),
                            created_at=instance.get('LaunchTime')
                        ))
        except Exception as e:
            logger.error(f"Error scanning EC2 instances: {str(e)}")
        return resources

    def _scan_sqs_queues(self):
        """Scans all SQS queues in the AWS region and returns a list of CloudResource objects."""
        resources = []
        try:
            sqs_client = self.session.client("sqs")
            response = sqs_client.list_queues()

            if "QueueUrls" in response:
                for queue_url in response["QueueUrls"]:
                    queue_attributes = sqs_client.get_queue_attributes(
                        QueueUrl=queue_url,
                        AttributeNames=["All"]
                    )
                    resources.append(CloudResource(
                        provider=CloudProvider.AWS,
                        resource_type=ResourceType.SQS_QUEUE,
                        identifier=queue_url,
                        metadata=queue_attributes["Attributes"]
                    ))
                    logger.info(f"Found SQS Queue: {queue_url}")
            return resources
        except Exception as e:
            logger.error(f"Error scanning SQS Queues: {e}")
        return []


    
    def _scan_lambda_functions(self) -> List[CloudResource]:
        """Scan Lambda functions"""
        resources = []
        try:
            paginator = self.lambda_client.get_paginator('list_functions')
            for page in paginator.paginate():
                for func in page['Functions']:
                    resources.append(CloudResource(
                        id=func['FunctionArn'],
                        name=func['FunctionName'],
                        provider=CloudProvider.AWS,
                        type=ResourceType.SERVERLESS,
                        region=self.region,
                        properties={
                            'runtime': func['Runtime'],
                            'memory': func['MemorySize'],
                            'timeout': func['Timeout'],
                            'handler': func['Handler'],
                            'code_size': func['CodeSize'],
                            'description': func.get('Description', ''),
                            'last_modified': func['LastModified']
                        },
                        created_at=datetime.strptime(func['LastModified'].split('.')[0], '%Y-%m-%dT%H:%M:%S')
                    ))
        except Exception as e:
            logger.error(f"Error scanning Lambda functions: {str(e)}")
        return resources

    def _scan_rds_instances(self) -> List[CloudResource]:
        """Scan RDS instances"""
        resources = []
        try:
            paginator = self.rds_client.get_paginator('describe_db_instances')
            for page in paginator.paginate():
                for db_instance in page['DBInstances']:
                    resources.append(CloudResource(
                        id=db_instance['DBInstanceArn'],
                        name=db_instance['DBInstanceIdentifier'],
                        provider=CloudProvider.AWS,
                        type=ResourceType.DATABASE,
                        region=self.region,
                        properties={
                            'engine': db_instance['Engine'],
                            'engine_version': db_instance['EngineVersion'],
                            'instance_class': db_instance['DBInstanceClass'],
                            'status': db_instance['DBInstanceStatus'],
                            'allocated_storage': db_instance['AllocatedStorage'],
                            'endpoint': db_instance.get('Endpoint', {}).get('Address'),
                            'port': db_instance.get('Endpoint', {}).get('Port'),
                            'multi_az': db_instance['MultiAZ'],
                            'vpc_id': db_instance.get('DBSubnetGroup', {}).get('VpcId'),
                            'availability_zone': db_instance['AvailabilityZone'],
                            'created_at': db_instance.get('InstanceCreateTime')
                        },
                        tags=self._convert_tags(db_instance.get('TagList', [])),
                        created_at=db_instance.get('InstanceCreateTime')
                    ))
        except Exception as e:
            logger.error(f"Error scanning RDS instances: {str(e)}")
        return resources

    def _scan_s3_buckets(self) -> List[CloudResource]:
        """Scan S3 buckets"""
        resources = []
        try:
            response = self.s3_client.list_buckets()
            for bucket in response['Buckets']:
                try:
                    location = self.s3_client.get_bucket_location(Bucket=bucket['Name'])['LocationConstraint'] or 'us-east-1'
                    if location == self.region:
                        resources.append(CloudResource(
                            id=f"arn:aws:s3:::{bucket['Name']}",
                            name=bucket['Name'],
                            provider=CloudProvider.AWS,
                            type=ResourceType.STORAGE,
                            region=self.region,
                            properties={
                                'creation_date': bucket['CreationDate'].isoformat(),
                                'location': location
                            },
                            created_at=bucket['CreationDate']
                        ))
                except ClientError as e:
                    logger.warning(f"Error getting location for bucket {bucket['Name']}: {str(e)}")
                    continue
        except Exception as e:
            logger.error(f"Error scanning S3 buckets: {str(e)}")
        return resources

    def _get_name_from_tags(self, tags: List[Dict]) -> str:
        """Extract name from AWS tags"""
        for tag in tags:
            if tag['Key'].lower() == 'name':
                return tag['Value']
        return 'unnamed'

    def _convert_tags(self, aws_tags: List[Dict]) -> Dict:
        """Convert AWS tags to standard format"""
        return {tag['Key']: tag['Value'] for tag in aws_tags}

    def get_dependencies(self, resource: CloudResource) -> Set[str]:
        """Get resource dependencies"""
        dependencies = set()
        try:
            if resource.type == ResourceType.COMPUTE:
                dependencies.update(self._get_ec2_dependencies(resource.id))
            elif resource.type == ResourceType.SERVERLESS:
                dependencies.update(self._get_lambda_dependencies(resource.id))
        except Exception as e:
            logger.error(f"Error getting dependencies for {resource.id}: {str(e)}")
        return dependencies

    def _get_ec2_dependencies(self, instance_id: str) -> Set[str]:
        """Get EC2 instance dependencies"""
        dependencies = set()
        try:
            instance = self.ec2_client.describe_instances(
                InstanceIds=[instance_id]
            )['Reservations'][0]['Instances'][0]
            
            # VPC dependencies
            if 'VpcId' in instance:
                dependencies.add(instance['VpcId'])
            
            # Security group dependencies
            for sg in instance.get('SecurityGroups', []):
                dependencies.add(sg['GroupId'])
            
            # Subnet dependency
            if 'SubnetId' in instance:
                dependencies.add(instance['SubnetId'])
            
            # EBS volume dependencies
            for device in instance.get('BlockDeviceMappings', []):
                if 'Ebs' in device:
                    dependencies.add(device['Ebs']['VolumeId'])
            
        except Exception as e:
            logger.error(f"Error getting EC2 dependencies: {str(e)}")
        return dependencies

    def _get_lambda_dependencies(self, function_name: str) -> Set[str]:
        """Get Lambda function dependencies"""
        dependencies = set()
        try:
            function = self.lambda_client.get_function(FunctionName=function_name)
            
            # VPC dependencies
            if 'VpcConfig' in function['Configuration']:
                vpc_config = function['Configuration']['VpcConfig']
                if 'VpcId' in vpc_config:
                    dependencies.add(vpc_config['VpcId'])
                for subnet in vpc_config.get('SubnetIds', []):
                    dependencies.add(subnet)
                for sg in vpc_config.get('SecurityGroupIds', []):
                    dependencies.add(sg)
            
            # Layer dependencies
            for layer in function['Configuration'].get('Layers', []):
                dependencies.add(layer['Arn'])
                
        except Exception as e:
            logger.error(f"Error getting Lambda dependencies: {str(e)}")
        return dependencies

class MultiCloudScanner:
    """Orchestrator for scanning multiple cloud providers"""
    
    def __init__(self):
        self.scanners: Dict[CloudProvider, CloudScanner] = {}
        
    def add_scanner(self, provider: CloudProvider, scanner: CloudScanner):
        """Add a cloud provider scanner"""
        self.scanners[provider] = scanner
        
    def scan_all(self) -> Dict[CloudProvider, List[CloudResource]]:
        """Scan all configured cloud providers"""
        results = {}
        
        for provider, scanner in self.scanners.items():
            logger.info(f"Starting scan for {provider.value}")
            if scanner.authenticate():
                results[provider] = scanner.scan_resources()
                logger.info(f"Completed scan for {provider.value}, found {len(results[provider])} resources")
            else:
                logger.warning(f"Skipping {provider.value} due to authentication failure")
                
        return results
    
    def analyze_dependencies(self, resources: Dict[CloudProvider, List[CloudResource]]) -> Dict:
        """Analyze dependencies across all cloud providers"""
        logger.info("Starting dependency analysis")
        cross_cloud_dependencies = {}
        all_resources = {}
        
        # Build resource map
        for provider_resources in resources.values():
            for resource in provider_resources:
                all_resources[resource.id] = resource
                
        # Analyze dependencies
        for resource_id, resource in all_resources.items():
            try:
                dependencies = self.scanners[resource.provider].get_dependencies(resource)
                cross_cloud_dependencies[resource_id] = {
                    'resource': resource,
                    'dependencies': [
                        {
                            'id': dep_id,
                            'provider': all_resources[dep_id].provider if dep_id in all_resources else None,
                            'type': all_resources[dep_id].type if dep_id in all_resources else None
                        }
                        for dep_id in dependencies
                    ]
                }
            except Exception as e:
                logger.error(f"Error analyzing dependencies for {resource_id}: {str(e)}")
                
        logger.info("Completed dependency analysis")
        return cross_cloud_dependencies


def scan_aws():
    """Real AWS scanning logic"""
    print("🔗 Connecting to real AWS...")

    ec2 = boto3.client("ec2", region_name="us-west-2")
    s3 = boto3.client("s3", region_name="us-west-2")
    rds = boto3.client("rds", region_name="us-west-2")

    # Fetch real AWS resources
    ec2_instances = ec2.describe_instances()
    s3_buckets = s3.list_buckets()
    rds_instances = rds.describe_db_instances()

    print("\n📡 AWS Resources (Real):")
    print("- EC2 Instances:", len(ec2_instances["Reservations"]))
    print("- S3 Buckets:", [b["Name"] for b in s3_buckets["Buckets"]])
    print("- RDS Instances:", [r["DBInstanceIdentifier"] for r in rds_instances["DBInstances"]])


import boto3
import random
import json
from moto import mock_aws

def _check_ec2_security(instance_id):
    """Simulate EC2 security check"""
    return random.random() > 0.5

def _check_s3_encryption(bucket_name):
    """Simulate S3 encryption check"""
    return random.random() > 0.4

def _check_rds_privacy(db_instance_id):
    """Simulate RDS privacy check"""
    return random.random() > 0.3

def detect_vulnerabilities(resources):
    """Dynamically analyze potential security risks"""
    vulnerabilities = []

    checks = [
        ('ec2_instances', _check_ec2_security, "Exposed Instances"),
        ('s3_buckets', _check_s3_encryption, "Unencrypted Buckets"),
        ('rds_instances', _check_rds_privacy, "Public Database Instances")
    ]

    for resource_type, check_func, vuln_msg in checks:
        vulnerable_resources = [r for r in resources[resource_type] if not check_func(r)]
        if vulnerable_resources:
            vulnerabilities.append(f"{vuln_msg}: {len(vulnerable_resources)} {resource_type.replace('_', ' ').title()}")

    return vulnerabilities

@mock_aws
def scan_mock(num_resources=3):
    """Dynamically mock AWS resources with vulnerability detection"""
    print("🎭 Dynamically Mocking AWS Resources...")

    # Initialize clients
    clients = {
        'iam': boto3.client('iam', region_name="us-west-2"),
        'ec2': boto3.client('ec2', region_name="us-west-2"),
        's3': boto3.client('s3', region_name="us-west-2"),
        'rds': boto3.client('rds', region_name="us-west-2"),
        'lambda': boto3.client('lambda', region_name="us-west-2"),
        'sqs': boto3.client('sqs', region_name="us-west-2")
    }

    # Resource tracking
    resources = {
        'ec2_instances': [],
        's3_buckets': [],
        'rds_instances': [],
        'lambda_functions': [],
        'sqs_queues': []
    }

    # IAM Role Creation Policy
    assume_role_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "lambda.amazonaws.com"},
            "Action": "sts:AssumeRole"
        }]
    }

    # Dynamic Resource Generation
    for _ in range(num_resources):
        # EC2 Instances
        ec2_response = clients['ec2'].run_instances(
            ImageId=f"ami-{random.randint(10000000, 99999999)}",
            MinCount=1, 
            MaxCount=1, 
            InstanceType="t2.micro"
        )
        resources['ec2_instances'].append(ec2_response['Instances'][0]['InstanceId'])

        # S3 Buckets
        bucket_name = f"dynamic-bucket-{random.randint(1000, 9999)}"
        clients['s3'].create_bucket(
            Bucket=bucket_name, 
            CreateBucketConfiguration={'LocationConstraint': "us-west-2"}
        )
        resources['s3_buckets'].append(bucket_name)

        # RDS Instances
        rds_instance_id = f"database-{random.randint(1000, 9999)}"
        clients['rds'].create_db_instance(
            DBInstanceIdentifier=rds_instance_id,
            DBInstanceClass="db.t2.micro",
            Engine="mysql",
            AllocatedStorage=20,
            MasterUsername="admin",
            MasterUserPassword=f"Pass{random.randint(10000, 99999)}!"
        )
        resources['rds_instances'].append(rds_instance_id)

        # Create IAM Role
        role_name = f"lambda-role-{random.randint(1000, 9999)}"
        role = clients['iam'].create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(assume_role_policy)
        )

        # Lambda Functions
        lambda_function_name = f"function-{random.randint(1000, 9999)}"
        clients['lambda'].create_function(
            FunctionName=lambda_function_name,
            Runtime="python3.8",
            Role=role['Role']['Arn'],
            Handler="index.handler",
            Code={'ZipFile': b'def handler(event, context): return {"statusCode": 200}'}
        )
        resources['lambda_functions'].append(lambda_function_name)

        # SQS Queues
        queue_name = f"queue-{random.randint(1000, 9999)}"
        clients['sqs'].create_queue(QueueName=queue_name)
        resources['sqs_queues'].append(queue_name)

    # Vulnerability Analysis
    vulnerabilities = detect_vulnerabilities(resources)
    
    print("\n🚨 Potential Vulnerabilities:")
    for vuln in vulnerabilities:
        print(f"- {vuln}")

    return resources


if __name__ == "__main__":
    choice = input("🌐 Do you want to connect to real AWS? (Y/N): ").strip().lower()
    if choice == "y":
        scan_aws()
    else:
        scan_mock()


def main():
    # Initialize scanner
    scanner = MultiCloudScanner()
    
    # Add AWS scanner
    try:
        aws_scanner = AWSScanner(region='ap-south-1', profile='default')  # Use your AWS profile
        scanner.add_scanner(CloudProvider.AWS, aws_scanner)
    except Exception as e:
        logger.error(f"Failed to initialize AWS scanner: {str(e)}")
        return
    
    # Scan resources
    results = scanner.scan_all()
    
    # Analyze dependencies
    dependencies = scanner.analyze_dependencies(results)
    
    # Print results
    for provider, resources in results.items():
        print(f"\n{provider.value.upper()} Resources:")
        for resource in resources:
            print(f"- {resource.name} ({resource.type.value})")
            
    print("\nDependencies:")
    for resource_id, info in dependencies.items():
        resource = info['resource']
        print(f"\n{resource.name} ({resource.provider.value}):")
        for dep in info['dependencies']:
            print(f"- Depends on: {dep['id']}")

if __name__ == "__main__":
    main()
