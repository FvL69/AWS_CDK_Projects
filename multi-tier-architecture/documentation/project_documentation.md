## Introduction:  

    In a multi-tier architecture, you can introduce 'extra layers of defense' between attackers and your   
    sensitive resources. In this  example, data is the most sensitive resource, so you would place it at the   
    end of a chain to introduce two more layers of defense between attackers and your data.    

    In fact, you don't need to expose parts of your application in the public subnet at all if you use   
    managed AWS endpoints, such as load balancers or Network Address Translation (NAT) options.      

**Diagram link:**  (projects initial diagram)    
[Diagram0](../includes/diagrams/diagram0.png)    

#### Layer 1: Internet access resources. (public subnets)     
    To limit exposure to the internet, you can use the following in your architecture:  
        1. An internet facing Application Load Balancer for incoming traffic.  
        2. A Nat solution (e.g. a NAT gateway or NAT instance) for outgoing traffic.  

#### Layer 2: Applications in private subnets with egress.      
    This VPC also has a layer of private subnets for applications, running on EC2 instances. There are   
    512 IP addresses reserved in each of these subnets to accommodate each application's need for scaling.   
    It will also accommodate new applications as the business's portfolio of applications expands.      

The Application Load Balancer attached to both public subnets distributes traffic between the application   
resources in the private subnets.      

#### Layer 3: Databases in isolated private subnets.    
    This design puts data resources into a second private subnet behind the first private subnet. This example   
    reserves fewer IP addresses than the application subnet but more IP addresses than the public subnet     
    (you probably need to scale application resources than the data resources behind the application).     

    The data layer can be a RDS deployment or a database running on an EC2. In either case, use a Multi-AZ   
    configuration, as shown here. The secondary could be a read replica or a standby configured to automatically   
    replace the primary should a failure occur.     

#### Extra IP addresses, additional 'reserved' isolated private subnets:  
    While you should always reserve more than enough IP addresses for your deployed infrastructure,     
    it's also important to leave some of the extra IP addresses of your VPC available for changes to     
    your network architecture by reserving additional subnets.     

    This architecture reserves 512 IP addresses in each private subnet. You can also just leave these   
    IP addresses entirely unreserved, if you prefer but the subnet numbering will be altered when deploying   
    these unreserved subnets/IP addresses.      

## Project constructs:  [AWS_CDK_Constructs](https://docs.aws.amazon.com/cdk/v2/guide/constructs.html)

    This project is, for the most part, build with 'L2 constructs', these are 'curated constructs' made by the AWS CDK team.     
    Which entails that: L2 constructs include sensible default property configurations, best practice security   
    policies, and generate a lot of the boilerplate code and glue logic for you.    

    Which makes life easier if you don't posses advanced knowledge of AWS services to be able to build with   
    L1 constructs yet.   
         

# Project steps:      

## 1. Create and configure the network: VPC, AZ's, Subnets and Gateways.   

### The Network.  

    Create a VPC, constisting of:  
    1. 2 AZ's (Availability Zones)  
    2. 1 IGW (Internet gateway)
    3. 2 NGW's (NAT gateway, one for each public subnet)   
    4. 4 subnets (per AZ):    
        - 1 public. (for connecting to the internet)  
        - 1 private with egress. (for access to the internet through a NAT gateway)  
        - 1 private isolated. (isolated subnets do not route from or to the Internet)  
        - 1 reserved private isolated. (for future expansion of network and services)  

**note:**    
If you configure the stack in the app.py file **for the AWS Account and Region that are implied by the current CLI configuration**,   
the max AZ's is 2 due to the fact that it's unknown in which region the app is going to be deployed. (there are regions with only 2 AZ's)  

ACL's, Routetables, SubnetRoutetableAssociations, logical routing (e.g, each Public Subnet will get a routetable with a route to the IGW),     
EIP's, Gateway attachments and a through an IAM policy restricted default SG will be created by the L2 Vpc construct.   


## 2. Create and configure AWS services: Security Groups, EC2 instances, RDS database, Application Load Balancer,    
## Target Group, Listener, ASG, EC2 Instance Connect Endpoint and IAM policy.   

**Diagram link** (version 1: added admin access)  
[Diagram1](../includes/diagrams/diagram1.png)

## The AWS services:
 
   ### 1. Associate Security Groups with the EC2's, RDSdb, ALB and EIC_Endpoint.
   **Purpose:**  
    A security group acts as firewall on the instance level. By default all outbound traffic is allowed but i've restricted   
    this feature for more fine grained control of the data traffic. There are exeptions of incomming traffic that is   
    allowed out despite the allow_all_outbound=False setting, e.g.: 

   **Difficulties:**  
    Just making sure that all the data traffic can find it's way to the intended services by applying the correct rules.  

   ### 2. Create an EC2 Instance (Linux 2023 AMI) in each ApplicationSubnet.  
   **Purpose:**  
   A web server in different AZ's for availability and DR.  

   **Difficulties:**  
   For file handling i use the python build-in 'with open()' function and stored the file object in a variable using:     
   user_data = ec2.UserData.for_linux().add_commands(f.read()) which worked, but after upgrading the aws cli to v2 the  
   user data file would not upload in my EC2's anymore. This got me a bit confused because initially my code worked.  
   Correct way: with open() ; user_data = f.read() ; self.user_data = ec2.UserData.for_linux().custom(user_data).   

   ### 3. Create an Application Load Balancer and attach it to the Public Subnets in both AZ's.  
   **Note:**   
   In case of an unhealthy target: check SG config or EC2 user data input.  

   ### 3a. Create a Target Group.

   ### 3b. Create a Listener

   ### 4. Create an Auto Scaling Group.

   ### 5. Create a RDS db in DatabaseSubnet1.  
    Note: When you enable the Multi-AZ property, RDS automatically selects appropriate AZ's for the primary and standby instances  

   ### 6. Create an EIC_Endpoint:  
 **Note:**   
 This is a L1 construct, a low lvl construct which uses a Cfn (Cloudformation) naming convention.  

 **Purpose:**  
 Intended specifically for management traffic use cases. The Service establishes a private tunnel from your computer to the endpoint   
 using the credentials for your IAM entity. Traffic is authenticated and authorized before it reaches your VPC.  

 **Difficulties:**  
 It was a bit of a search to figure out the correct parameter syntax for the EIC attributes and IAM policy.   
 For advice and quick search i use Amazone Q, e.g. i didn't know which endpoint to use for reaching an EC2 without a public IP.    
    
    EIC_Endpoint benefits:  
        - Allows access to private instances which have no public IP.  
        - It leverages IAM for access control. (provides fine-grained permissions management)  
        - It eliminates the need to manage SSH keys for each instance.  
        - Connection attempts are logged in AWS CloudTrail. (auditing purposes)  
        - No additional costs but for cross AZ data transfer, see link DataTransferCosts below.

**Links to service documentation:**   
   [EC2InstanceConnect_Endpoint](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/connect-with-ec2-instance-connect-endpoint.html)  
   [DataTransferCosts](https://aws.amazon.com/ec2/pricing/on-demand/#Data_Transfer_within_the_same_AWS_Region)  


   ### 6a. Create IAM Policy for EIC Endpoint.

## 3. Configure: SG rules, ACL rules and routing.

