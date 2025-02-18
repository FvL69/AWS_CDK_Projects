## Introduction:  

    In a multi-tier architecture, you can introduce 'extra layers of defense' between attackers and your   
    sensitive resources. In this  example, data is the most sensitive resource, so you would place it at the   
    end of a chain to introduce two more layers of defense between attackers and your data.    

    In fact, you don't need to expose parts of your application in the public subnet at all if you use   
    managed AWS endpoints, such as load balancers or Network Address Translation (NAT) options.      

**Diagram link:**  (projects initial diagram)    
[Diagram0](../diagrams/diagram0.png)    

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

## Project constructs:  
[AWS_CDK_Constructs](https://docs.aws.amazon.com/cdk/v2/guide/constructs.html)  

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


## 2. Create and configure AWS services: Network Access Control Lists (ACL's), Security Groups, EC2 launch template, RDS database, Application Load Balancer,    
## Target Group, ASG, Listener, EC2 Instance Connect Endpoint and IAM policy.   

**Diagram link** (version 1: added admin access)  
[Diagram1](../diagrams/diagram1.png)

## The AWS services:

   ### 1. Attach ACL's to the appropriate subnets and create the appropriate rules needed.  
   **Purpose:** 
   - I created one ACL for similar subnets in both AZ's, this reduces complexity and maintenance overhead and matches my architectures defence layers as intended.    
   - Also is there less chance of misconfiguration when updating rules.    
   - Ephemeral ports (1024-65535) rules added between all subnets for responses to handle multiple client requests at the same time.  
   - DNS port rules between all subnets, it solved the unhealthy targets problem after i implemented the NACL's. Pointed out by Amazon Q.
   
   **Findings:**  
   - Making sure that all services can communicate as intended. Every ingress rule has an egress counter part due to the stateless nature of the network ACL.

 
   ### 2. Associate Security Groups with the EC2 launch template, RDSdb, ALB and EIC_Endpoint.

   **Purpose:**  
    A security group acts as firewall on the instance level. By default all outbound traffic is allowed but i've restricted   
    this feature for more fine grained control of the data traffic. 

   **Findings:**  
    Just making sure that all the data traffic can find it's way restricted solely to the intended services by applying the correct rules.  

   ### 3. Create an EC2 Instance (Linux 2023 AMI) in each ApplicationSubnet.  
   **Purpose:**  
   A web server in different AZ's for availability and DR.  

   **Findings:**  
   For file handling i use the python build-in 'with open()' function and stored the file object in a variable using:     
   user_data = ec2.UserData.for_linux().add_commands(f.read()) which worked, but after upgrading the aws cli to v2 the  
   user data file would not upload in my EC2's anymore. This got me a bit confused because initially my code worked.  
   Correct way: with open() ; user_data = f.read() ; self.user_data = ec2.UserData.for_linux().custom(user_data).   

   ### 4. Create an Application Load Balancer and attach it to the Public Subnets in both AZ's.  
     
   

   ### 4a. Create a Target Group.
   A target group is used to route requests to one or more registered targets.
   
   **Note:** 
   In case of an unhealthy target: check SG config or EC2 user data input.  

   The key is balancing between:
   - Fast deployment/scaling (lower threshold)  
   - System stability (higher threshold)  

   ### 4b. Create a HTTPS Listener.
   **purpose:**  
   A listener checks for connection requests.  
   To create an HTTPS listener, you must deploy at least one SSL server certificate on your load balancer.  
   The load balancer decrypt requests from clients before sending them to the targets.  
   Also specify a security policy, which is used to negotiate secure connections between clients and the load balancer.  

   - Configure Iam Policy  

   Listener config:  
   - ACM certificate (self signed) for SSL/TLS termination.   
   - Default_action prop: forward to target group.     

   **Findings:**  
   To configure certificates: Sequence[IListenerCertificate] but the API reference only provides the attribute and   
   no methods! So it wouldn't cdk synth. I learned that concrete classes provide the actual implementations and  
   static factory methods. In this case: elbv2.ListenerCertificate.from_arn(self.certificate_arn).   

   ### 5. Create an Auto Scaling Group.
   AWS CLI to verify the attachment status:  
   aws autoscaling describe-traffic-sources --auto-scaling-group-name my-asg  

   Target Tracking Scaling enabled:  
   The AutoScaling construct library will create the required CloudWatch alarms and AutoScaling policies.  

   ### 6. Create a RDS db in DatabaseSubnet1.  
   **Note:**   
    When you enable the Multi-AZ property, RDS automatically selects appropriate AZ's for the primary and standby instances.  
    Also, the database security group applies automatically to both the primary and standby DB instances.  

   **Purpose:**  
   - DB created in private isolated subnet, reachable only from EC2 web server in another private subnet.
   - To store web server data.

   **Findings:**  
   - Installing mariadb105 as a SQL client for connecting to DB. (EC2 user-data)    
   - Because of secure VPC/subnet setup just using password auth for connecting to DB only from EC2's.  
   - For AdminGroup: Configure read-only access in MYSQL (DB), and read-only access for RDS service lvl with IAM Policy. (Stack)  


   ### 7. Create an EIC_Endpoint:  
 **Note:**   
 This is a L1 construct, a low lvl construct which uses a Cfn (Cloudformation) naming convention.  

 **Purpose:**  
 Intended specifically for secure management traffic use cases. The Service establishes a private tunnel from your computer to the endpoint   
 using the credentials for your IAM entity. Traffic is authenticated and authorized before it reaches your VPC.  

 **Findings:**  
 It was a bit of a search to figure out the correct property syntax for the EIC attributes and IAM policy.   
 For advice and quick search i use Amazone Q, e.g. i didn't know which endpoint to use for connecting with EC2 without a public IP.    

 Added a RemovalPolicy.Destroy in case of a stack update so i don't need to manually delete the EIC Endpoint.  
    
    EIC_Endpoint benefits:  
        - No need for bastion hosts  
        - No need to manage SSH keys  
        - No public IP addresses required on your instances  
        - IAM-controlled access  
        - Full SSH functionality including system updates  

**Links to service documentation:**   
   [EC2InstanceConnect_Endpoint](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/connect-with-ec2-instance-connect-endpoint.html)  
   [DataTransferCosts](https://aws.amazon.com/ec2/pricing/on-demand/#Data_Transfer_within_the_same_AWS_Region)  


### 8. Create a ROUTE 53 Alias record pointing to the ALB.  
   **Purpose:**  
   User Request -> Route 53 -> ALB -> EC2 instances in Private Subnets -> Web Servers

   ROUTE 53 is the AWS DNS service. Any requests made to the webservers can use my fvldev.net domain name instead    
   of the ALB's DNS name which is more user friendly.   
   I've created an Alias Record for my Public Hosted Zone which is necessary if you want to map     
   a host name to an AWS service, in this case the Application Load Balancer.   

   **Findings:**  
   For an Alias record you can also use the apex domain name, fvldev.net, by leaving the record_name property empty.  
   So basically i've created an A record, A = IPv4, of which i created an Alias record in my Public Hosted Zone.  
   The target= property is where the Alias config is done. In contrast to other record types, an Alias record  
   needs no TTL set because AWS uses the default TTL of the service the hostname points to.  

   **note:**  

        I've tried to implement: aws_cdk.aws_route53.IHostedZone(), but that didn't work.   
        To make it work i needed to use: aws_cdk.aws_route53.HostedZone(). 
        The key difference is that IHostedZone is an interface, while HostedZone is a concrete class that implements that interface.  

        According to Amazon Q:  
        An interface (IHostedZone) only defines what properties and methods should exist, but doesn't provide the actual implementation.  
        It's like a contract or blueprint.

[Diagram2](../diagrams/diagram2.png)
### 9. Create ROUTE 53 endpoint health check (ALB).  

   **Purpose:**  
   To monitor the health of the Application Load Balancer. The health check will send HTTP requests to the FQDN   
   to determine if the ALB is responding properly.   
   (I will upgrade to HTTPS requests)    

   **Finding:**  


### XX. Create nested IAM stack.  

   **Purpose:**  
   To remove all IAM Policies/Roles from main stack to enhance the organization and maintainability of the projects infrastructure.  

   **Findings:**  
   Creating a new class called IamStack() with the necessary parameters to enable cross stack references for the local  
   constructs and inheritance from the NestedStack class declaring it as a nested stack from the main stack.     
   The IamStack instance in the main stack will be treated as a single construct, as all the other constructs   
   in the stack. It also brings it into the main stacks scope for deployment.   
     





