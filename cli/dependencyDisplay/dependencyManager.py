from rich.console import Console
from rich.tree import Tree

def display_dependency_graph_terminal(dependency_data: dict) -> None:
    """
    Build and display a dependency graph from dependency_data in the terminal
    as a tree-like structure using the Rich library.
    
    The dependency_data should be a dictionary with keys like "cloud" and "application",
    each containing a list of dependency dictionaries. Each dependency dict is expected
    to have at least the keys:
        - name
        - version
        - riskLevel
        - dependencies (a list of names of dependencies)
        
    In this version, a main project node is created, and all initial parent nodes (roots)
    are attached as its children.
    """
    # Merge dependencies from all sections into one dictionary.
    nodes = {}
    for section in dependency_data:
        for dep in dependency_data[section]:
            nodes[dep["name"]] = dep

    # Build a dictionary to count incoming edges for each node.
    incoming = {name: 0 for name in nodes}
    for dep in nodes.values():
        for child in dep.get("dependencies", []):
            if child in incoming:
                incoming[child] += 1

    # Find roots: nodes with no incoming dependencies.
    roots = [name for name, count in incoming.items() if count == 0]
    if not roots:
        # If no clear roots are found (e.g., cycles), consider all nodes as roots.
        roots = list(nodes.keys())

    def build_tree(dep_name: str, nodes: dict, visited: set = None) -> Tree:
        """
        Recursively build a Rich Tree for a given dependency.
        If a cycle is detected (i.e. a dependency already visited in the current branch),
        a "[Cycle detected]" marker is added.
        """
        if visited is None:
            visited = set()
            
        tree_label = f"{dep_name} (v{nodes[dep_name].get('version', 'N/A')}, risk: {nodes[dep_name].get('riskLevel', 'N/A')})"
        tree = Tree(tree_label)
        
        if dep_name in visited:
            tree.add("[Cycle detected]")
            return tree

        new_visited = visited.union({dep_name})
        for child in nodes[dep_name].get("dependencies", []):
            if child in nodes:
                tree.add(build_tree(child, nodes, new_visited))
            else:
                tree.add(f"{child} [Not Found]")
        return tree

    console = Console()
    console.print("[bold underline]Dependency Graph:[/bold underline]\n")

    # Create a main project node.
    main_tree = Tree("[bold]Main Project[/bold]")

    # Attach each root tree as a child of the main project node.
    for root in roots:
        main_tree.add(build_tree(root, nodes))
    
    console.print(main_tree)

if __name__ == "__main__":
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

    # Visualize the dependency graph in the terminal.
    display_dependency_graph_terminal(sample_data)
