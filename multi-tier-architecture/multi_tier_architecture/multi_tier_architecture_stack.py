from aws_cdk import (
    Stack,
    aws_iam as iam,
    aws_ec2 as ec2,
    aws_elasticloadbalancingv2 as elbv2,
    aws_elasticloadbalancingv2_targets as elbv2_target,
    aws_autoscaling as autoscaling,
    aws_rds as rds,
    Duration,
    RemovalPolicy,
    CfnTag,
)
from constructs import Construct
import uuid

class MultiTierArchitectureStack(Stack):

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        self.vpc = ec2.Vpc(
            self, "VPC",
            ip_addresses=ec2.IpAddresses.cidr("10.0.0.0/20"), # A /20 cidr gives 4096 ip addresses to work with.
            create_internet_gateway=True,
            enable_dns_hostnames=True,
            enable_dns_support=True,
            max_azs=2,
            nat_gateways=2,
            # Creating 3 subnets in each AZ as layers of defense to secure sensitive data, plus reserving 
            # an extra private subnet for future changes of the network architecture.
            subnet_configuration=[
                ec2.SubnetConfiguration(cidr_mask=25, name="Ingress", subnet_type=ec2.SubnetType.PUBLIC),
                ec2.SubnetConfiguration(cidr_mask=23, name="Application", subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS),
                ec2.SubnetConfiguration(cidr_mask=24, name="Database", subnet_type=ec2.SubnetType.PRIVATE_ISOLATED),
                ec2.SubnetConfiguration(cidr_mask=23, name="reserved", subnet_type=ec2.SubnetType.PRIVATE_ISOLATED, reserved=True),
            ]
        )

        
        ### SECURITY GROUPS ###

        # Security Group for AppInstance1.
        self.SG_App1 = ec2.SecurityGroup(
            self, "SG_App1",
            vpc=self.vpc,
            allow_all_outbound=False,
            description="Security Group for AppInstance1",
            security_group_name="SG_App1",
        )

        # Security Group for AppInstance2.
        self.SG_App2 = ec2.SecurityGroup(
            self, "SG_App2",
            vpc=self.vpc,
            allow_all_outbound=False,
            description="Security Group for AppInstance2",
            security_group_name="SG_App2",
        )

        # Security Group for Application Load Balancer.
        self.SG_ALB = ec2.SecurityGroup(
            self, "SG_ALB",
            vpc=self.vpc,
            allow_all_outbound=False,
            description="Security Group for ALB",
            security_group_name="SG_ALB",
        )

        # Security Group for RDS database.
        self.SG_RDSdb = ec2.SecurityGroup(
            self, "SG_RDSdb",
            vpc=self.vpc,
            allow_all_outbound=False,
            description="Security Group for RDSdb",
            security_group_name="SG_RDSdb",
        )

        # Security Group for EIC_Endpoint.
        self.SG_EIC_Endpoint = ec2.SecurityGroup(
            self, "SG_EIC_Endpoint",
            vpc=self.vpc,
            allow_all_outbound=False,
            description="Security Group for EIC_Endpoint",
            security_group_name="SG_EIC_Endpoint",
        )



        ### EC2 INSTANCES, APPLICATION LOAD BALANCER, TARGET GROUP, LISTENER, Auto Scaling Group and RDS DATABASE ###
        

        # Import and encode the 'user-data.sh' file to implement a basic web server for both EC2 instances.
        with open("multi_tier_architecture/user-data.sh", "r") as f:
            user_data = f.read()

        self.user_data = ec2.UserData.for_linux().custom(user_data)


        # EC2 instance ApplicationSubnet1.
        self.AppInstance1 = ec2.Instance(
            self, "AppInstance1",
            instance_type=ec2.InstanceType("t2.micro"),
            machine_image=ec2.AmazonLinuxImage(generation=ec2.AmazonLinuxGeneration.AMAZON_LINUX_2023),
            vpc=self.vpc,
            availability_zone=self.vpc.availability_zones[0],
            vpc_subnets=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS),
            block_devices=[ec2.BlockDevice(
                device_name="/dev/xvda", 
                volume=ec2.BlockDeviceVolume.ebs(
                    volume_size=30,
                    delete_on_termination=True,
                    iops=3000,
                    volume_type=ec2.EbsDeviceVolumeType.GP3,
                    )
                )
            ],
            security_group=self.SG_App1,
            user_data=self.user_data,
            private_ip_address="10.0.2.20",
        )
            
        
        # EC2 instance ApplicationSubnet2.
        self.AppInstance2 = ec2.Instance(
            self, "AppInstance2",
            instance_type=ec2.InstanceType("t2.micro"),
            machine_image=ec2.AmazonLinuxImage(generation=ec2.AmazonLinuxGeneration.AMAZON_LINUX_2023),
            vpc=self.vpc,
            availability_zone=self.vpc.availability_zones[1],
            vpc_subnets=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS),
            block_devices=[ec2.BlockDevice(
                device_name="/dev/xvda",
                volume=ec2.BlockDeviceVolume.ebs(
                    volume_size=30,
                    delete_on_termination=True,
                    iops=3000,
                    volume_type=ec2.EbsDeviceVolumeType.GP3,
                    )
                )
            ],
            security_group=self.SG_App2,
            user_data=self.user_data,
            private_ip_address="10.0.4.20",
        )


        # Application Load Balancer.
        self.alb = elbv2.ApplicationLoadBalancer(
            self, "ALB",
            vpc=self.vpc,
            desync_mitigation_mode=elbv2.DesyncMitigationMode.DEFENSIVE,
            http2_enabled=True,
            idle_timeout=Duration.seconds(60),
            security_group=self.SG_ALB,
            internet_facing=True,
            ip_address_type=elbv2.IpAddressType.IPV4,
            vpc_subnets=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PUBLIC),
            drop_invalid_header_fields=False,
        )

        # Target group.
        self.targetgroup = elbv2.ApplicationTargetGroup(
            self, "TargetGroup",
            vpc=self.vpc,
            load_balancing_algorithm_type=elbv2.TargetGroupLoadBalancingAlgorithmType.ROUND_ROBIN,
            port=80,
            protocol=elbv2.ApplicationProtocol.HTTP,
            target_type=elbv2.TargetType.INSTANCE,
            target_group_name="TargetGroup",
            health_check=elbv2.HealthCheck(
                port="80",
                protocol=elbv2.Protocol.HTTP,
                healthy_http_codes="200-299",
                healthy_threshold_count=5,
                interval=Duration.seconds(30),
                path="/",
                timeout=Duration.seconds(5),
                unhealthy_threshold_count=2,
            ),
        )
        
        # Add targets to the target group.
        self.targetgroup.add_target(elbv2_target.InstanceTarget(self.AppInstance1))
        self.targetgroup.add_target(elbv2_target.InstanceTarget(self.AppInstance2))


        # HTTP listener.
        self.HTTP_listener = self.alb.add_listener(
            "HTTP_listener",
            default_target_groups=[self.targetgroup],
            port=80,
            open=True,
        )

        # Auto Scaling Group.
        self.asg = autoscaling.AutoScalingGroup(
            self, "ASG",
            vpc=self.vpc,

        )

        
        
        # RDS database. 
        self.RDSdb = rds.DatabaseInstance(
            self, "RDSdb",
            engine=rds.DatabaseInstanceEngine.MYSQL,
            instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE3, ec2.InstanceSize.MICRO),
            vpc=self.vpc,
            availability_zone=self.vpc.availability_zones[0],
            multi_az=False, # If True: RDS will automatically create and manage a standby replica in a different AZ. 
            publicly_accessible=False,
            vpc_subnets=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PRIVATE_ISOLATED),
            security_groups=[self.SG_RDSdb],
            instance_identifier="MyRdsInstance",
            removal_policy=RemovalPolicy.DESTROY,
            storage_type=rds.StorageType.GP3,
            allocated_storage=20,
            max_allocated_storage=20,
            backup_retention=Duration.days(0),
            delete_automated_backups=True,
            deletion_protection=False
        )



        ### SECURITY GROUP RULES ###

        # Application Load Balancer Ingress rules.
        # Ingress rule for internet access.
        self.SG_ALB.add_ingress_rule(
            peer=ec2.Peer.ipv4("0.0.0.0/0"),
            connection=ec2.Port.tcp(80),
            description="Allow inbound HTTP traffic from Internet.",
        )

        # # Application Load Balancer Egress rules.
        # Egress rule to SG_App1.
        self.SG_ALB.add_egress_rule(
            peer=self.SG_App1,
            connection=ec2.Port.tcp(80),
            description="Allow outbound HTTP traffic to AppInstance1",
        )
        # Egress rule to SG_App2.
        self.SG_ALB.add_egress_rule(
            peer=self.SG_App2,
            connection=ec2.Port.tcp(80),
            description="Allow outbound HTTP traffic to AppInstance2",
        )


        # AppInstance1 ingress rules.
        # Ingress rule from EIC Endpoint.
        self.SG_App1.add_ingress_rule(
            peer=self.SG_EIC_Endpoint,
            connection=ec2.Port.tcp(22),
            description="Allow inbound SSH traffic from EIC_Endpoint",
        )
        # Ingress rule from ALB.
        self.SG_App1.add_ingress_rule(
            peer=self.SG_ALB,
            connection=ec2.Port.tcp(80),
            description="Allow inbound HTTP traffic from SG_ALB",
        )
        # Ingress rule from RDSdb.
        self.SG_App1.add_ingress_rule(
            peer=self.SG_RDSdb,
            connection=ec2.Port.tcp(3306),
            description="Allow inbound MySQL traffic from SG_RDSdb",
        )

        # AppInstance1 Egress rules.
        # Egress rule to EIC Endpoint.
        self.SG_App1.add_egress_rule(
            peer=self.SG_EIC_Endpoint,
            connection=ec2.Port.tcp(22),
            description="Allow outbound SSH traffic to EIC_Endpoint",
        )
        # Egress rule to SG_ALB.
        self.SG_App1.add_egress_rule(
            peer=self.SG_ALB,
            connection=ec2.Port.tcp(80),
            description="Allow outbound HTTP traffic to SG_ALB",
        )
        # Egress rule to SG_RDSdb.
        self.SG_App1.add_egress_rule(
            peer=self.SG_RDSdb,
            connection=ec2.Port.tcp(3306),
            description="Allow outbound MySQL traffic to SG_RDSdb",
        )
        # Egress rule to NATGateway on port 80.
        self.SG_App1.add_egress_rule(
            peer=ec2.Peer.ipv4("0.0.0.0/0"),
            connection=ec2.Port.tcp(80),
            description="Allow outbound HTTP traffic to NatGateway",
        )
        # Egress rule to NatGateway on port 443.
        self.SG_App1.add_egress_rule(
            peer=ec2.Peer.ipv4("0.0.0.0/0"),
            connection=ec2.Port.tcp(443),
            description="Allow outbound HTTPS traffic to NatGateway",
        )


        # AppInstance2 Ingress rules.
        # Ingress rule from EIC Endpoint.
        self.SG_App2.add_ingress_rule(
            peer=self.SG_EIC_Endpoint,
            connection=ec2.Port.tcp(22),
            description="Allow inbound SSH traffic from EIC_Endpoint",
        )
        # Ingress rule from ALB.
        self.SG_App2.add_ingress_rule(
            peer=self.SG_ALB,
            connection=ec2.Port.tcp(80),
            description="Allow inbound HTTP traffic from SG_ALB",
        )
        # Ingress rule from RDSdb.
        self.SG_App2.add_ingress_rule(
            peer=self.SG_RDSdb,
            connection=ec2.Port.tcp(3306),
            description="Allow inbound MySQL traffic from SG_RDSdb",
        )

        # AppInstance2 Egress rules.
        # Egress rule to EIC Endpoint.
        self.SG_App2.add_egress_rule(
            peer=self.SG_EIC_Endpoint,
            connection=ec2.Port.tcp(22),
            description="Allow outbound SSH traffic to EIC_Endpoint",
        )
        # Egress rule to SG_ALB.
        self.SG_App2.add_egress_rule(
            peer=self.SG_ALB,
            connection=ec2.Port.tcp(80),
            description="Allow outbound HTTP traffic to SG_ALB",
        )
        # Egress rule to SG_RDSdb.
        self.SG_App2.add_egress_rule(
            peer=self.SG_RDSdb,
            connection=ec2.Port.tcp(3306),
            description="Allow outbound MySQL traffic to SG_RDSdb",
        )
        # Egress rule to NATGateway on port 80.
        self.SG_App2.add_egress_rule(
            peer=ec2.Peer.ipv4("0.0.0.0/0"),
            connection=ec2.Port.tcp(80),
            description="Allow outbound HTTP traffic to NatGateway",
        )
        # Egress rule to NatGateway on port 443.
        self.SG_App2.add_egress_rule(
            peer=ec2.Peer.ipv4("0.0.0.0/0"),
            connection=ec2.Port.tcp(443),
            description="Allow outbound HTTPS traffic to NatGateway",
        )


        # RDS database Ingress rules.
        # Ingress rule from AppInstance1.
        self.SG_RDSdb.add_ingress_rule(
            peer=self.SG_App1,
            connection=ec2.Port.tcp(3306),
            description="Allow inbound MySQL traffic from SG_App1",
        )
        # Ingress rule from AppInstance2.
        self.SG_RDSdb.add_ingress_rule(
            peer=self.SG_App2,
            connection=ec2.Port.tcp(3306),
            description="Allow inbound MySQL traffic from SG_App2",
        )

        # RDS database Egress rules.
        # Egress rule to SG_App1.
        self.SG_RDSdb.add_egress_rule(
            peer=self.SG_App1,
            connection=ec2.Port.tcp(3306),
            description="Allow outbound MySQL traffic to SG_App1",
        )
        # Egress rule to SG_App2.
        self.SG_RDSdb.add_egress_rule(
            peer=self.SG_App2,
            connection=ec2.Port.tcp(3306),
            description="Allow outbound MySQL traffic to SG_App2",
        )


        # EIC Endpoint Ingress rules.
        # Ingress rule for AWS API calls.
        self.SG_EIC_Endpoint.add_ingress_rule(
            peer=ec2.Peer.ipv4("0.0.0.0/0"),
            connection=ec2.Port.tcp(443),
            description="Allow inbound HTTPS traffic for AWS API calls"
        )
        # Ingress rule from AppInstance1.
        self.SG_EIC_Endpoint.add_ingress_rule(
            peer=self.SG_App1,
            connection=ec2.Port.tcp(22),
            description="Allow inbound SSH traffic from SG_App1",
        )
        # Ingress rule from AppInstance2.
        self.SG_EIC_Endpoint.add_ingress_rule(
            peer=self.SG_App2,
            connection=ec2.Port.tcp(22),
            description="Allow inbound SSH traffic from SG_App2",
        )        
        
        # EIC Endpoint Egress rules.
        # Egress rule for AWS API calls.
        self.SG_EIC_Endpoint.add_egress_rule(
            peer=ec2.Peer.ipv4("0.0.0.0/0"),
            connection=ec2.Port.tcp(443),
            description="Allow outbound HTTPS traffic for AWS API calls"
        )
        # Egress rule to SG_App1.
        self.SG_EIC_Endpoint.add_egress_rule(
            peer=self.SG_App1,
            connection=ec2.Port.tcp(22),
            description="Allow outbound SSH traffic to SG_App1",
        )
        # Egress rule to SG_App2.
        self.SG_EIC_Endpoint.add_egress_rule(
            peer=self.SG_App2,
            connection=ec2.Port.tcp(22),
            description="Allow outbound SSH traffic to SG_App2",
        )


        ### EIC_ENDPOINT and IAM POLICY ###

        # EC2 Instance Connect Endpoint.
        self.EIC_Endpoint = ec2.CfnInstanceConnectEndpoint(
            self, "ec2InstanceConnectEndpoint",
            # Client_token prevents duplicates when retrying stack creation or modification of the EIC Endpoint itself.
            client_token=str(uuid.uuid4()), 
            preserve_client_ip=True, 
            subnet_id=self.vpc.select_subnets(
                availability_zones=[self.vpc.availability_zones[0]],
                subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS).subnets[0].subnet_id,
            security_group_ids=[self.SG_EIC_Endpoint.security_group_id],
            tags=[CfnTag(key="Name", value="EIC_Endpoint")],
        )


        # Create the Enpoint IAM policy and an AdminGroup to attach the IAM policy to.
        # Any work force users would be added to the AdminGroup manually in the console.
        
        # Set variable eic_subnet_id to indicate specific subnet in: PolicyStatement => resources config.
        eic_subnet_id = self.vpc.select_subnets(
                availability_zones=[self.vpc.availability_zones[0]],
                subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS).subnets[0].subnet_id

        # Identity-based IAM policy to create, describe and delete EIC Endpoint.
        self.EIC_Endpoint_Policy = iam.Policy(
            self, "EICEndpointPolicy",
            statements=[
                iam.PolicyStatement(
                    sid="EICEndpointPolicy",
                    effect=iam.Effect.ALLOW,
                    actions=[
                        "ec2:CreateInstanceConnectEndpoint",
                        "ec2:CreateNetworkInterface",
                        "ec2:CreateTags",
                        "ec2:DescribeInstanceConnectEndpoints",
                        "ec2:DeleteInstanceConnectEndpoint",
                        "iam:CreateServiceLinkedRole",
                    ],
                    # .region and .account are properties of the Stack instance that gives you 
                    # the AWS region and account ID where the stack will be deployed.
                    resources=[f"arn:aws:ec2:{self.region}:{self.account}:{eic_subnet_id}"],
                ),
                iam.PolicyStatement(
                    sid="CreateNetworkInterface",
                    effect=iam.Effect.ALLOW,
                    actions=[
                        "ec2:CreateNetworkInterface"
                    ],
                    resources=[f"arn:aws:ec2:{self.region}:{self.account}:security-group/*"]
                ),
                iam.PolicyStatement(
                    sid="DescribeInstanceConnectEndpoints",
                    effect=iam.Effect.ALLOW,
                    actions=[
                        "ec2:DescribeInstanceConnectEndpoints"
                    ],
                    resources=["*"]
                )
            ]   
        )       

        # Adding additional permissions to use EC2 Instance Connect Endpoint to connect to instances.
        self.EIC_Endpoint_Policy.add_statements(
            iam.PolicyStatement(
                sid="EC2InstanceConnect",
                actions=["ec2-instance-connect:openTunnel"],
                effect=iam.Effect.ALLOW,
                resources=[f"arn:aws:ec2:{self.region}:{self.account}:instance-connect-endpoint/{self.EIC_Endpoint.attr_id}"],
                conditions={
                    "NumericEquals": {
                        "ec2-instance-connect:remotePort": 22,
                    },
                    "IpAddress": {
                        "ec2-instance-connect:privateIpAddress": [
                            "10.0.2.0/23", # CIDR range for AppInstance1
                            "10.0.4.0/23", # CIDR range for AppInstance2
                        ],
                    },
                    "NumericLessThanEquals": {
                        "ec2-instance-connect:maxTunnelDuration": 3600,
                    }
                }
            ),
            iam.PolicyStatement(
                sid="SSHPublicKey",
                actions=["ec2-instance-connect:SendSSHPublicKey"],
                effect=iam.Effect.ALLOW,
                resources=["*"],
                conditions={
                    "StringEquals": {
                        "ec2:osuser": "ec2-user"
                    },
                },
            ),
            iam.PolicyStatement(
                sid="Describe",
                actions=[
                    "ec2:DescribeInstances",
                    "ec2:DescribeInstanceConnectEndpoint",
                ],
                effect=iam.Effect.ALLOW,
                resources=["*"],
            )
        )


        # Create an IAM Group of Users.
        self.AdminGroup = iam.Group(
            self, "AdminGroup",
            group_name="AdminGroup",
        )

        # Attach Endpoint policy to AdminGroup.
        self.EIC_Endpoint_Policy.attach_to_group(self.AdminGroup)
