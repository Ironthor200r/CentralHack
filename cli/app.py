import click
import sys
from typing import Optional
from login.login import login_to_aws
from dependencyDisplay.dependencyManager import display_dependency_graph_terminal
from CADAT.badal import badalIChooseYou

ASCII_ART = r"""
 $$$$$$\   $$$$$$\ $$$$$$$$\  $$$$$$\       $$$$$$$$\  $$$$$$\   $$$$$$\  $$\       
$$  __$$\ $$  __$$\\__$$  __|$$  __$$\      \__$$  __|$$  __$$\ $$  __$$\ $$ |      
$$ /  $$ |$$ /  \__|  $$ |   $$ /  $$ |        $$ |   $$ /  $$ |$$ /  $$ |$$ |      
$$ |  $$ |$$ |        $$ |   $$$$$$$$ |$$$$$$\ $$ |   $$ |  $$ |$$ |  $$ |$$ |      
$$ |  $$ |$$ |        $$ |   $$  __$$ |\______|$$ |   $$ |  $$ |$$ |  $$ |$$ |      
$$ |  $$ |$$ |  $$\   $$ |   $$ |  $$ |        $$ |   $$ |  $$ |$$ |  $$ |$$ |      
 $$$$$$  |\$$$$$$  |  $$ |   $$ |  $$ |        $$ |    $$$$$$  | $$$$$$  |$$$$$$$$\ 
 \______/  \______/   \__|   \__|  \__|        \__|    \______/  \______/ \________|
"""

def print_welcome():
    click.echo(ASCII_ART)

@click.group()
def cli() -> None:
    print_welcome()

@cli.command()
@click.option('--verbose', '-v', is_flag=True, help='Enable verbose output')
def hello(verbose: bool) -> None:
    """Simple command example"""
    if verbose:
        click.echo('Running in verbose mode')

@cli.command()
def login() -> None:
    """Call the login function"""
    if not login_to_aws():
        sys.exit(1)

@cli.command()
def cloudanal() -> None:
    """Run the cloud analysis tool"""
    badalIChooseYou()

@cli.command()
def depgraph() -> None:
    """Display the dependency graph"""
    # Sample dependency data
    sample_data = {
        "cloud": [
            {
                "name": "aws-sdk",
                "version": "^3.1.0",
                "type": "cloud",
                "category": "AWS",
                "failurePoints": [
                    "API Rate Limiting",
                    "Network Timeout",
                    "Authentication Failure",
                    "Region Availability"
                ],
                "dependencies": ["aws-lambda", "aws-s3"],
                "riskLevel": "high",
                "uptime": "99.95%",
                "lastIncident": "2024-01-15"
            },
            { 
                "name": "aws-lambda",
                "version": "^2.0.0",
                "type": "cloud",
                "category": "AWS",
                "failurePoints": [
                    "Cold Start Delays",
                    "Memory Limits",
                    "Timeout Issues"
                ],
                "dependencies": ["aws-sdk"],
                "riskLevel": "medium",
                "uptime": "99.99%",
                "lastIncident": "2024-02-01"
            },
            { 
                "name": "aws-s3",
                "version": "^3.0.0",
                "type": "cloud",
                "category": "AWS",
                "failurePoints": [
                    "Storage Quota",
                    "Transfer Speed",
                    "Access Permissions"
                ],
                "dependencies": ["aws-sdk"],
                "riskLevel": "low",
                "uptime": "99.99%",
                "lastIncident": "2023-12-10"
            },
            { 
                "name": "azure-storage",
                "version": "^12.1.0",
                "type": "cloud",
                "category": "Azure",
                "failurePoints": [
                    "Connection Timeout",
                    "Storage Quota Exceeded",
                    "Replication Lag"
                ],
                "dependencies": ["@azure/identity"],
                "riskLevel": "medium",
                "uptime": "99.95%",
                "lastIncident": "2024-01-20"
            },
            { 
                "name": "@azure/identity",
                "version": "^3.0.0",
                "type": "cloud",
                "category": "Azure",
                "failurePoints": [
                    "Token Expiration",
                    "Authentication Failure",
                    "Service Principal Issues"
                ],
                "dependencies": [],
                "riskLevel": "high",
                "uptime": "99.90%",
                "lastIncident": "2024-02-05"
            }
        ],
        "application": [
            { 
                "name": "react",
                "version": "^18.2.0",
                "type": "application",
                "category": "Frontend",
                "failurePoints": [
                    "Memory Leak",
                    "Render Performance",
                    "State Management Issues"
                ],
                "dependencies": ["react-dom"],
                "riskLevel": "low",
                "usage": "Critical",
                "lastUpdate": "2024-01-10"
            },
            { 
                "name": "react-dom",
                "version": "^18.2.0",
                "type": "application",
                "category": "Frontend",
                "failurePoints": [
                    "DOM Updates",
                    "Event Handling",
                    "Browser Compatibility"
                ],
                "dependencies": [],
                "riskLevel": "low",
                "usage": "Critical",
                "lastUpdate": "2024-01-10"
            },
            { 
                "name": "express",
                "version": "^4.18.2",
                "type": "application",
                "category": "Backend",
                "failurePoints": [
                    "Request Timeout",
                    "Memory Overflow",
                    "Connection Limits"
                ],
                "dependencies": ["body-parser", "cors"],
                "riskLevel": "medium",
                "usage": "Critical",
                "lastUpdate": "2024-01-15"
            },
            { 
                "name": "body-parser",
                "version": "^1.20.0",
                "type": "application",
                "category": "Backend",
                "failurePoints": [
                    "Payload Size Limits",
                    "Parse Errors",
                    "Memory Usage"
                ],
                "dependencies": [],
                "riskLevel": "low",
                "usage": "Required",
                "lastUpdate": "2023-12-20"
            },
            { 
                "name": "cors",
                "version": "^2.8.5",
                "type": "application",
                "category": "Backend",
                "failurePoints": [
                    "Security Configuration",
                    "Browser Support",
                    "Preflight Requests"
                ],
                "dependencies": [],
                "riskLevel": "medium",
                "usage": "Required",
                "lastUpdate": "2023-11-30"
            },
            { 
                "name": "mongoose",
                "version": "^7.5.0",
                "type": "application",
                "category": "Database",
                "failurePoints": [
                    "Connection Pool",
                    "Query Performance",
                    "Schema Validation"
                ],
                "dependencies": [],
                "riskLevel": "high",
                "usage": "Critical",
                "lastUpdate": "2024-01-25"
            },
            { 
                "name": "redux",
                "version": "^4.2.0",
                "type": "application",
                "category": "State Management",
                "failurePoints": [
                    "State Updates",
                    "Action Handling",
                    "Store Configuration"
                ],
                "dependencies": ["react-redux"],
                "riskLevel": "medium",
                "usage": "Critical",
                "lastUpdate": "2024-01-05"
            },
            { 
                "name": "react-redux",
                "version": "^8.0.5",
                "type": "application",
                "category": "State Management",
                "failurePoints": [
                    "Component Updates",
                    "Store Connection",
                    "Selector Performance"
                ],
                "dependencies": ["redux"],
                "riskLevel": "medium",
                "usage": "Critical",
                "lastUpdate": "2024-01-05"
            }
        ]
    }
    display_dependency_graph_terminal(sample_data)

# Check if no command is passed, and run hello by default
def main() -> Optional[int]:
    try:
        # If no command is provided, explicitly call `hello` command
        if len(sys.argv) == 1:
            sys.argv.append('hello')
        
        cli()
        return 0
    except Exception as e:
        click.echo(f'Error: {str(e)}', err=True)
        return 1

if __name__ == '__main__':
    sys.exit(main())
