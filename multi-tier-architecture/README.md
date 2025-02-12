# Multi-Tier-Architecture project.  

The goal of this project is to show how to strengthen security by customizing an Amazon VPC, and limit  
exposure to resources in this VPC by making use of a multi-tier architecture.     

I learned about these concepts in the AWS Skill Builder Networking Core course and the challenge for me is to  
translate the diagram into Infrastructure as Code (IaC) using CDK Python. 

The diagram link below is the initial diagram as depicted in the Skill Builder Networking Core course, in the projects    
documentation you'll find diagram links that follow the evolvement of the project as i will introduce new AWS services for   
practical improvement to the project infrastructure.         

Diagram link: [Diagram](./includes/diagrams/diagram1.png)  

Project docs: [Project_documentation](./includes//documentation/project_documentation.md)       

Project code: [MainStack](./multi_tier_architecture/multi_tier_architecture_stack.py)  

Project code: [SecurityStack(nested)](./security/iam_stack.py)
