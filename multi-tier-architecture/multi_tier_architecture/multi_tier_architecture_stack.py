from aws_cdk import (
    Stack,
    aws_iam as iam,
    aws_ec2 as ec2,
    aws_elasticloadbalancingv2 as elbv2,
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

        # Create VPC.
        self.vpc = ec2.Vpc(
            self, "VPC",
            ip_addresses=ec2.IpAddresses.cidr("10.0.0.0/20"), # A /20 cidr gives 4096 ip addresses to work with.
            create_internet_gateway=True,
            enable_dns_hostnames=True,
            enable_dns_support=True,
            max_azs=2,
            nat_gateways=2,
            # Creating 3 subnets in each AZ as separate layers of defense to secure sensitive data, 
            # plus reserving an extra private subnet for future changes of the network architecture.
            subnet_configuration=[
                ec2.SubnetConfiguration(cidr_mask=25, name="Ingress", subnet_type=ec2.SubnetType.PUBLIC),
                ec2.SubnetConfiguration(cidr_mask=23, name="Application", subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS),
                ec2.SubnetConfiguration(cidr_mask=24, name="Database", subnet_type=ec2.SubnetType.PRIVATE_ISOLATED),
                ec2.SubnetConfiguration(cidr_mask=23, name="reserved", subnet_type=ec2.SubnetType.PRIVATE_ISOLATED, reserved=True),
            ]
        )


        ###  NETWORK ACCESS CONTROL LISTS  ###

        # Public ACL.
        self.publicAcl = ec2.NetworkAcl(
            self, "PublicSubnetNacl",
            vpc=self.vpc,
            network_acl_name="PublicSubnetNACL",
            subnet_selection=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PUBLIC)
        )

        # Private with Egress ACL.
        self.privEgressAcl = ec2.NetworkAcl(
            self, "PrivEgressSubnetNacl",
            vpc=self.vpc,
            network_acl_name="PrivateWithEgressSubnetNACL",
            subnet_selection=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS)
        )

        # Private Isolated ACL.
        self.PrivIsoAcl = ec2.NetworkAcl(
            self, "PrivIsoSubnetNacl",
            vpc=self.vpc,
            network_acl_name="PrivateIsolatedSubnetNACL",
            subnet_selection=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PRIVATE_ISOLATED)
        )


        
        ###  SECURITY GROUPS  ###

        # Security Group for AppInstances.
        self.SG_AppInstances = ec2.SecurityGroup(
            self, "SG_AppInstances",
            vpc=self.vpc,
            allow_all_outbound=False,
            description="Security Group for AppInstances",
            security_group_name="SG_AppInstances",
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



        ###  EIC_ENDPOINT and IAM POLICIES  ###

        # EC2 Instance Connect Endpoint for secure connection with EC2's in private subnets.
        self.EIC_Endpoint = ec2.CfnInstanceConnectEndpoint(
            self, "ec2InstanceConnectEndpoint",
            client_token=str(uuid.uuid4()), # Prevents duplicates when retrying stack creation or modification of the EIC Endpoint itself.
            preserve_client_ip=True, 
            subnet_id=self.vpc.select_subnets(
                availability_zones=[self.vpc.availability_zones[0]],
                subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS).subnets[0].subnet_id,
            security_group_ids=[self.SG_EIC_Endpoint.security_group_id],
            tags=[CfnTag(key="Name", value="EIC_Endpoint")],
        )


        # Create the Enpoint IAM policy and an AdminGroup to attach the IAM policy to.
        # Any work force users would be added to the AdminGroup manually in the console.
        
        # Set variable eic_subnet_id.
        eic_subnet_id = self.vpc.select_subnets(
                availability_zones=[self.vpc.availability_zones[0]],
                subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS).subnets[0].subnet_id

        # IAM policy to create, describe and delete EIC Endpoint.
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

        # Adding additional permissions to use EIC Endpoint to connect to instances.
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
                            "10.0.2.0/23", # AZ1
                            "10.0.4.0/23", # AZ2
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


        # Create an IAM Group-of-Users.
        self.AdminGroup = iam.Group(
            self, "AdminGroup",
            group_name="AdminGroup",
        )

        # Attach Endpoint policy to AdminGroup.
        self.EIC_Endpoint_Policy.attach_to_group(self.AdminGroup)
        


        ###  KEY PAIR, USER DATA  ###
        
        # Create key pair for EC2 launch template.
        self.AdminKeyPair = ec2.KeyPair(
            self, "AdminKeyPair",
            key_pair_name="AdminKeyPair",
            type=ec2.KeyPairType.RSA,
            format=ec2.KeyPairFormat.PEM,
            account=f"{self.account}",
            region=f"{self.region}",
        )


        # Import and encode file for launch template user_data.
        with open("multi_tier_architecture/user-data.sh", "r") as f:
            user_data = f.read()

        self.user_data = ec2.UserData.for_linux().custom(user_data)



        ###  lAUNCH TEMPLATE IAM POLICY, EC2 LAUNCH TEMPLATE, AUTO SCALING GROUP, APPLICATION LOAD BALANCER, TARGET GROUP, LISTENER  ###


        # Create IAM Policy for launch template.
        self.launchTemplatePolicy = iam.Policy(
            self, "LaunchTemplatePolicy",
            statements=[
                iam.PolicyStatement(
                    sid="LaunchTemplateAndInstanceActions",
                    actions=[
                        "ec2:RunInstances",
                        "ec2:DescribeLaunchTemplates",
                        "ec2:DescribeLaunchTemplateVersions",
                    ],
                    effect=iam.Effect.ALLOW,
                    resources=[
                        f"arn:aws:ec2:{self.region}:{self.account}:instance/*",
                        f"arn:aws:ec2:{self.region}:{self.account}:volume/*",
                        f"arn:aws:ec2:{self.region}:{self.account}:network-interface/*",
                        f"arn:aws:ec2:{self.region}:{self.account}:security-group/*",
                        f"arn:aws:ec2:{self.region}:{self.account}:subnet/*",
                    ],
                ),
                iam.PolicyStatement(
                    sid="CreateAndDeleteLaunchTemplate",
                    actions=[
                        "ec2:CreateLaunchTemplate",
                        "ec2:DeleteLaunchTemplate",
                    ],
                    effect=iam.Effect.ALLOW,
                    resources=[f"arn:aws:ec2:{self.region}:{self.account}:launch-template/*"],
                ),
                iam.PolicyStatement(
                    sid="Describe",
                    actions=[
                        "ec2:DescribeLaunchTemplates",
                        "ec2:DescribeLaunchTemplateVersions",
                    ],
                    effect=iam.Effect.ALLOW,
                    resources=["*"],
                ),
                iam.PolicyStatement(
                    sid="KeyPairAccess",
                    actions=["ec2:DescribeKeyPairs"],
                    effect=iam.Effect.ALLOW,
                    resources=[f"arn:aws:ec2:{self.region}:{self.account}:key-pair/{self.AdminKeyPair.key_pair_name}"],
                ),
                iam.PolicyStatement(
                    sid="AMIAccess",
                    actions=["ec2:DescribeImages"],
                    effect=iam.Effect.ALLOW,
                    resources=["*"],
                ),
            ],
        )
        # Attach policy to AdminGroup.
        self.launchTemplatePolicy.attach_to_group(self.AdminGroup)


        # EC2 launch template for ASG.
        self.launchTemplate = ec2.LaunchTemplate(
            self, "EC2LaunchTemplate",
            launch_template_name="WebServerLaunchTemplate",
            version_description="WebServerTemplate",
            machine_image=ec2.AmazonLinuxImage(generation=ec2.AmazonLinuxGeneration.AMAZON_LINUX_2023),
            instance_type=ec2.InstanceType("t2.micro"),
            key_pair=self.AdminKeyPair,
            security_group=self.SG_AppInstances,
            block_devices=[ec2.BlockDevice(
                device_name="/dev/xvda",
                volume=ec2.BlockDeviceVolume.ebs(
                    volume_size=30,
                    delete_on_termination=True,
                    iops=3000,
                    volume_type=ec2.EbsDeviceVolumeType.GP3,
                )
            )],
            user_data=self.user_data,
        )


        # Auto Scaling Group.
        self.asg = autoscaling.AutoScalingGroup(
            self, "ASG",
            vpc=self.vpc,
            launch_template=self.launchTemplate,
            min_capacity=2,
            desired_capacity=None, # Adjust this value in console.
            max_capacity=4,
            cooldown=Duration.minutes(4),
            vpc_subnets=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS),
            auto_scaling_group_name="ASG",
        )
        # Enable target tracking scaling policy for ASG.
        self.asg.scale_on_cpu_utilization(
            "CPUScaling",
            target_utilization_percent=40,
            cooldown=Duration.minutes(4),
        )
        

        # Application Load Balancer.
        self.alb = elbv2.ApplicationLoadBalancer(
            self, "ALB",
            vpc=self.vpc,
            vpc_subnets=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PUBLIC),
            internet_facing=True,
            http2_enabled=True,
            cross_zone_enabled=True,
            security_group=self.SG_ALB,
            preserve_host_header=True,
            x_amzn_tls_version_and_cipher_suite_headers=True,
            preserve_xff_client_port=True,
            xff_header_processing_mode=elbv2.XffHeaderProcessingMode.APPEND,
            ip_address_type=elbv2.IpAddressType.IPV4, 
            idle_timeout=Duration.seconds(60),
            desync_mitigation_mode=elbv2.DesyncMitigationMode.DEFENSIVE,
            drop_invalid_header_fields=True,
        )


        # Application Target group.
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
        # Register ASG as a target to TG.
        self.targetgroup.add_target(self.asg)


        # Certificate for HTTPS listener.
        self.certificate_arn =f"arn:aws:acm:{self.region}:{self.account}:certificate/c4f47c92-45c2-44de-8f6b-eda56017be76"

        # HTTPS listener.
        self.HTTPS_listener = self.alb.add_listener(
            "HTTPS_listener",
            certificates=[elbv2.ListenerCertificate.from_arn(self.certificate_arn)],
            default_action=elbv2.ListenerAction.forward(target_groups=[self.targetgroup]),
            port=443,
            protocol=elbv2.ApplicationProtocol.HTTPS,
            ssl_policy=elbv2.SslPolicy.RECOMMENDED_TLS, 
            open=True,
        )

        

        ###  RDS DATABASE, RDS IAM Policy  ###

        # RDS database. 
        self.RDSdb = rds.DatabaseInstance(
            self, "RDSdb",
            engine=rds.DatabaseInstanceEngine.MYSQL,
            instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE3, ec2.InstanceSize.MICRO),
            vpc=self.vpc,
            availability_zone=self.vpc.availability_zones[0],
            multi_az=False, # If True: RDS will create and manage a synchronous, standby replica in a different AZ. 
            publicly_accessible=False,
            iam_authentication=True,
            vpc_subnets=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PRIVATE_ISOLATED),
            security_groups=[self.SG_RDSdb],
            instance_identifier="MyRdsInstance",
            removal_policy=RemovalPolicy.DESTROY,
            storage_type=rds.StorageType.GP3,
            allocated_storage=20,
            max_allocated_storage=20,
            backup_retention=Duration.days(7), 
            delete_automated_backups=True,
            deletion_protection=False
        )


        # IAM policy 'ReadOnlyAccess' for Admingroup.
        self.RDSReadOnlyPolicy = iam.Policy(
            self, "RDSReadOnlyPolicy",
            statements=[
                iam.PolicyStatement(
                    sid="AllowRead",
                    actions=[
                        "rds:Describe*",
                        "rds:ListTagsForResource",
                    ],
                    effect=iam.Effect.ALLOW,
                    resources=[
                        f"arn:aws:rds:{self.region}:{self.account}:db:MyRdsInstance",
                    ],
                ),
            ],
        )
        # Attach policy to grand AdminGroup service lvl access. (view in console, describe instances, etc.)     
        self.RDSReadOnlyPolicy.attach_to_group(self.AdminGroup)



        ###  NETWORK ACL RULES  ###

        # Subnet CIDR ranges as CONSTANTS for clarity in ACL rule definition and easy maintenance.
        PUBLIC_AZ1 = "10.0.0.0/25"
        PUBLIC_AZ2 = "10.0.0.128/25"
        PRIVATE_EGRESS_AZ1 = "10.0.2.0/23"
        PRIVATE_EGRESS_AZ2 = "10.0.4.0/23"
        PRIVATE_ISOLATED_AZ1 = "10.0.6.0/24"
        PRIVATE_ISOLATED_AZ2 = "10.0.7.0/24"


        # PUBLIC SUBNET ACL
        # Ingress Rules
        self.publicAcl.add_entry(
            "publicSubnetAcl_IngressFromAnywhere_HTTP",
            cidr=ec2.AclCidr.ipv4("0.0.0.0/0"), # Incomming requests denied.
            rule_number=100,
            traffic=ec2.AclTraffic.tcp_port(80),
            direction=ec2.TrafficDirection.INGRESS,
            rule_action=ec2.Action.DENY,
        )

        self.publicAcl.add_entry(
            "publicSubnetAcl_IngressFromAnywhere_HTTPS",
            cidr=ec2.AclCidr.ipv4("0.0.0.0/0"), # Incomming requests granted.
            rule_number=120,
            traffic=ec2.AclTraffic.tcp_port(443),
            direction=ec2.TrafficDirection.INGRESS,
            rule_action=ec2.Action.ALLOW,
        )

        self.publicAcl.add_entry(
            "publicSubnetAcl_IngressFromPrivateEgressAZ1_HTTP",
            cidr=ec2.AclCidr.ipv4(PRIVATE_EGRESS_AZ1), # TG health checks.
            rule_number=140,
            traffic=ec2.AclTraffic.tcp_port(80),
            direction=ec2.TrafficDirection.INGRESS,
            rule_action=ec2.Action.ALLOW,
        )

        self.publicAcl.add_entry(
            "publicSubnetAcl_IngressFromPrivateEgressAZ2_HTTP",
            cidr=ec2.AclCidr.ipv4(PRIVATE_EGRESS_AZ2), # TG health checks.
            rule_number=160,
            traffic=ec2.AclTraffic.tcp_port(80),
            direction=ec2.TrafficDirection.INGRESS,
            rule_action=ec2.Action.ALLOW,
        )


        # PUBLIC SUBNET ACL
        # Egress Rules
        self.publicAcl.add_entry(
            "publicSubnetAcl_EgressToAnywhere_HTTP",
            cidr=ec2.AclCidr.ipv4("0.0.0.0/0"), # Web server response.
            rule_number=100,
            traffic=ec2.AclTraffic.tcp_port(80),
            direction=ec2.TrafficDirection.EGRESS,
            rule_action=ec2.Action.ALLOW,
        )

        self.publicAcl.add_entry(
            "publicSubnetAcl_EgressToAnywhere_HTTPS",
            cidr=ec2.AclCidr.ipv4("0.0.0.0/0"), # Web server response.
            rule_number=120,
            traffic=ec2.AclTraffic.tcp_port(443),
            direction=ec2.TrafficDirection.EGRESS,
            rule_action=ec2.Action.ALLOW,
        )

        self.publicAcl.add_entry(
            "publicSubnetAcl_EgressToPrivateEgressAZ1_HTTP",
            cidr=ec2.AclCidr.ipv4(PRIVATE_EGRESS_AZ1), # ALB traffic, TG health checks.
            rule_number=140,
            traffic=ec2.AclTraffic.tcp_port(80),
            direction=ec2.TrafficDirection.EGRESS,
            rule_action=ec2.Action.ALLOW,
        )

        self.publicAcl.add_entry(
            "publicSubnetAcl_EgressToPrivateEgressAZ2_HTTP",
            cidr=ec2.AclCidr.ipv4(PRIVATE_EGRESS_AZ2), # ALB traffic, TG health checks.
            rule_number=160,
            traffic=ec2.AclTraffic.tcp_port(80),
            direction=ec2.TrafficDirection.EGRESS,
            rule_action=ec2.Action.ALLOW,
        )


        # PRIVATE with EGRESS SUBNET ACL
        # Ingress Rules
        self.privEgressAcl.add_entry(
            "privateEgressSubnetAcl_IngressFromPublicAZ1_HTTP",
            cidr=ec2.AclCidr.ipv4(PUBLIC_AZ1), # ALB traffic, TG health checks.
            rule_number=100,
            traffic=ec2.AclTraffic.tcp_port(80),
            direction=ec2.TrafficDirection.INGRESS,
            rule_action=ec2.Action.ALLOW,
        )

        self.privEgressAcl.add_entry(
            "privateEgressSubnetAcl_IngressFromPublicAZ2_HTTP",
            cidr=ec2.AclCidr.ipv4(PUBLIC_AZ2), # ALB traffic, TG health checks.
            rule_number=120,
            traffic=ec2.AclTraffic.tcp_port(80),
            direction=ec2.TrafficDirection.INGRESS,
            rule_action=ec2.Action.ALLOW,
        )

        self.privEgressAcl.add_entry(
            "privateEgressSubnetAcl_IngressFromPrivateIsoAZ1_MYSQL",
            cidr=ec2.AclCidr.ipv4(PRIVATE_ISOLATED_AZ1), # RDS DB traffic.
            rule_number=140,
            traffic=ec2.AclTraffic.tcp_port(3306),
            direction=ec2.TrafficDirection.INGRESS,
            rule_action=ec2.Action.ALLOW,
        )

        self.privEgressAcl.add_entry(
            "privateEgressSubnetAcl_IngressToPrivateIsoAZ2_MYSQL",
            cidr=ec2.AclCidr.ipv4(PRIVATE_ISOLATED_AZ2), # RDS DB traffic in case of DR.
            rule_number=160,
            traffic=ec2.AclTraffic.tcp_port(3306),
            direction=ec2.TrafficDirection.INGRESS,
            rule_action=ec2.Action.ALLOW,
        )

        self.privEgressAcl.add_entry(
            "privateEgressSubnetAcl_IngressFromAnywhere_HTTPS",
            cidr=ec2.AclCidr.ipv4("0.0.0.0/0"), # EIC Endpoint HTTPS for AWS API calls
            rule_number=180,
            traffic=ec2.AclTraffic.tcp_port(443),
            direction=ec2.TrafficDirection.INGRESS,
            rule_action=ec2.Action.ALLOW,
        )

        self.privEgressAcl.add_entry(
            "privateEgressSubnetAcl_IngressFromPrivEgressAZ1_SSH",
            cidr=ec2.AclCidr.ipv4(PRIVATE_EGRESS_AZ1), # Internal SSH traffic with EC2's.
            rule_number=200,
            traffic=ec2.AclTraffic.tcp_port(22),
            direction=ec2.TrafficDirection.INGRESS,
            rule_action=ec2.Action.ALLOW,
        )

        self.privEgressAcl.add_entry(
            "privateEgressSubnetAcl_IngressFromPrivEgressAZ2_SSH",
            cidr=ec2.AclCidr.ipv4(PRIVATE_EGRESS_AZ2), # Internal SSH traffic with EC2's.
            rule_number=220,
            traffic=ec2.AclTraffic.tcp_port(22),
            direction=ec2.TrafficDirection.INGRESS,
            rule_action=ec2.Action.ALLOW,
        )


        # PRIVATE with EGRESS SUBNET ACL
        # Egress Rules
        self.privEgressAcl.add_entry(
            "privateEgressSubnetAcl_EgressToPublicAZ1_HTTP",
            cidr=ec2.AclCidr.ipv4(PUBLIC_AZ1), # TG health checks.
            rule_number=100,
            traffic=ec2.AclTraffic.tcp_port(80),
            direction=ec2.TrafficDirection.EGRESS,
            rule_action=ec2.Action.ALLOW,
        )

        self.privEgressAcl.add_entry(
            "privateEgressSubnetAcl_EgressToPublicAZ2_HTTP",
            cidr=ec2.AclCidr.ipv4(PUBLIC_AZ2), # TG health checks.
            rule_number=120,
            traffic=ec2.AclTraffic.tcp_port(80),
            direction=ec2.TrafficDirection.EGRESS,
            rule_action=ec2.Action.ALLOW,
        )

        self.privEgressAcl.add_entry(
            "privateEgressSubnetAcl_EgressToPrivateIsoAZ1_MYSQL",
            cidr=ec2.AclCidr.ipv4(PRIVATE_ISOLATED_AZ1), # RDS DB traffic.
            rule_number=140,
            traffic=ec2.AclTraffic.tcp_port(3306),
            direction=ec2.TrafficDirection.EGRESS,
            rule_action=ec2.Action.ALLOW,
        )

        self.privEgressAcl.add_entry(
            "privateEgressSubnetAcl_EgressToPrivateIsoAZ2_MYSQL",
            cidr=ec2.AclCidr.ipv4(PRIVATE_ISOLATED_AZ2), # RDS DB traffic in case of DR.
            rule_number=160,
            traffic=ec2.AclTraffic.tcp_port(3306),
            direction=ec2.TrafficDirection.EGRESS,
            rule_action=ec2.Action.ALLOW,
        )

        self.privEgressAcl.add_entry(
            "privateEgressSubnetAcl_EgressToAnywhere_HTTPS",
            cidr=ec2.AclCidr.ipv4("0.0.0.0/0"), # EIC Endpoint HTTPS traffic for AWS API calls
            rule_number=180,
            traffic=ec2.AclTraffic.tcp_port(443),
            direction=ec2.TrafficDirection.EGRESS,
            rule_action=ec2.Action.ALLOW,
        )

        self.privEgressAcl.add_entry(
            "privateEgressSubnetAcl_EgressToPrivEgressAZ1_SSH",
            cidr=ec2.AclCidr.ipv4(PRIVATE_EGRESS_AZ1), # Internal SSH traffic with EC2's.
            rule_number=200,
            traffic=ec2.AclTraffic.tcp_port(22),
            direction=ec2.TrafficDirection.EGRESS,
            rule_action=ec2.Action.ALLOW,
        )

        self.privEgressAcl.add_entry(
            "privateEgressSubnetAcl_EgressToPrivEgressAZ2_SSH",
            cidr=ec2.AclCidr.ipv4(PRIVATE_EGRESS_AZ2), # Internal SSH traffic with EC2's.
            rule_number=220,
            traffic=ec2.AclTraffic.tcp_port(22),
            direction=ec2.TrafficDirection.EGRESS,
            rule_action=ec2.Action.ALLOW,
        )


        # PRIVATE ISOLATED SUBNET ACL
        # Ingress Rules
        self.PrivIsoAcl.add_entry(
            "privateIsolatedSubnetAcl_IngressFromPrivEgressAZ1_MYSQL",
            cidr=ec2.AclCidr.ipv4(PRIVATE_EGRESS_AZ1), # DB traffic.
            rule_number=100,
            traffic=ec2.AclTraffic.tcp_port(3306),
            direction=ec2.TrafficDirection.INGRESS,
            rule_action=ec2.Action.ALLOW,
        )

        self.PrivIsoAcl.add_entry(
            "privateIsolatedSubnetAcl_IngressFromPrivEgressAZ2_MYSQL",
            cidr=ec2.AclCidr.ipv4(PRIVATE_EGRESS_AZ2), # DB traffic.
            rule_number=120,
            traffic=ec2.AclTraffic.tcp_port(3306),
            direction=ec2.TrafficDirection.INGRESS,
            rule_action=ec2.Action.ALLOW,
        )

        self.PrivIsoAcl.add_entry(
            "privateIsolatedSubnetAcl_IngressFromPrivIsolatedAZ1_MYSQL",
            cidr=ec2.AclCidr.ipv4(PRIVATE_ISOLATED_AZ1), # DB traffic in case of DR.
            rule_number=140,
            traffic=ec2.AclTraffic.tcp_port(3306),
            direction=ec2.TrafficDirection.INGRESS,
            rule_action=ec2.Action.ALLOW,
        )

        self.PrivIsoAcl.add_entry(
            "privateIsolatedSubnetAcl_IngressFromPrivIsolatedAZ2_MYSQL",
            cidr=ec2.AclCidr.ipv4(PRIVATE_ISOLATED_AZ2), # DB traffic in case of DR.
            rule_number=160,
            traffic=ec2.AclTraffic.tcp_port(3306),
            direction=ec2.TrafficDirection.INGRESS,
            rule_action=ec2.Action.ALLOW,
        )

        # PRIVATE ISOLATED SUBNET ACL
        # Egress Rules
        self.PrivIsoAcl.add_entry(
            "privateIsolatedSubnetAcl_EgressToPrivEgressAZ1_MYSQL",
            cidr=ec2.AclCidr.ipv4(PRIVATE_EGRESS_AZ1),
            rule_number=100,
            traffic=ec2.AclTraffic.tcp_port(3306),
            direction=ec2.TrafficDirection.EGRESS,
            rule_action=ec2.Action.ALLOW,
        )

        self.PrivIsoAcl.add_entry(
            "privateIsolatedSubnetAcl_EgressToPrivEgressAZ2_MYSQL",
            cidr=ec2.AclCidr.ipv4(PRIVATE_EGRESS_AZ2),
            rule_number=120,
            traffic=ec2.AclTraffic.tcp_port(3306),
            direction=ec2.TrafficDirection.EGRESS,
            rule_action=ec2.Action.ALLOW,
        )

        self.PrivIsoAcl.add_entry(
            "privateIsolatedSubnetAcl_EgressToPrivIsolatedAZ1_MYSQL",
            cidr=ec2.AclCidr.ipv4(PRIVATE_ISOLATED_AZ1), # DB traffic in case of DR.
            rule_number=140,
            traffic=ec2.AclTraffic.tcp_port(3306),
            direction=ec2.TrafficDirection.EGRESS,
            rule_action=ec2.Action.ALLOW,
        )

        self.PrivIsoAcl.add_entry(
            "privateIsolatedSubnetAcl_EgressToPrivIsolatedAZ2_MYSQL",
            cidr=ec2.AclCidr.ipv4(PRIVATE_ISOLATED_AZ2), # DB traffic in case of DR.
            rule_number=160,
            traffic=ec2.AclTraffic.tcp_port(3306),
            direction=ec2.TrafficDirection.EGRESS,
            rule_action=ec2.Action.ALLOW,
        )



        ### SECURITY GROUP RULES ###

        # Application Load Balancer Ingress rules.
        # Ingress rule for HTTPS requests.
        self.SG_ALB.add_ingress_rule(
            peer=ec2.Peer.ipv4("0.0.0.0/0"),
            connection=ec2.Port.tcp(443),
            description="Allow inbound HTTPS traffic from anywhere.",
        )
        # Ingress rule from SG_AppInstances.
        self.SG_ALB.add_ingress_rule(
            peer=self.SG_AppInstances,
            connection=ec2.Port.tcp(80),
            description="Allow inbound HTTP traffic from SG_AppInstances"
        )

        # Application Load Balancer Egress rules.
        # Egress rule to SG_AppInstances.
        self.SG_ALB.add_egress_rule(
            peer=self.SG_AppInstances,
            connection=ec2.Port.tcp(80),
            description="Allow outbound HTTP traffic to SG_AppInstances",
        )


        # AppInstances ingress rules.
        # Ingress rule from EIC Endpoint.
        self.SG_AppInstances.add_ingress_rule(
            peer=self.SG_EIC_Endpoint,
            connection=ec2.Port.tcp(22),
            description="Allow inbound SSH traffic from EIC_Endpoint",
        )
        # Ingress rule from ALB.
        self.SG_AppInstances.add_ingress_rule(
            peer=self.SG_ALB,
            connection=ec2.Port.tcp(80),
            description="Allow inbound HTTP traffic from SG_ALB",
        )
        # Ingress rule from RDSdb.
        self.SG_AppInstances.add_ingress_rule(
            peer=self.SG_RDSdb,
            connection=ec2.Port.tcp(3306),
            description="Allow inbound MySQL traffic from SG_RDSdb",
        )

        # AppInstances Egress rules.
        # Egress rule to EIC Endpoint.
        self.SG_AppInstances.add_egress_rule(
            peer=self.SG_EIC_Endpoint,
            connection=ec2.Port.tcp(22),
            description="Allow outbound SSH traffic to EIC_Endpoint",
        )
        # Egress rule to SG_ALB.
        self.SG_AppInstances.add_egress_rule(
            peer=self.SG_ALB,
            connection=ec2.Port.tcp(80),
            description="Allow outbound HTTP traffic to SG_ALB",
        )
        # Egress rule to SG_RDSdb.
        self.SG_AppInstances.add_egress_rule(
            peer=self.SG_RDSdb,
            connection=ec2.Port.tcp(3306),
            description="Allow outbound MySQL traffic to SG_RDSdb",
        )
        # Egress rule to anywhere on port 80.
        self.SG_AppInstances.add_egress_rule(
            peer=ec2.Peer.ipv4("0.0.0.0/0"),
            connection=ec2.Port.tcp(80),
            description="Allow outbound HTTP traffic through NatGateway",
        )
        # Egress rule to anywhere on port 443.
        self.SG_AppInstances.add_egress_rule(
            peer=ec2.Peer.ipv4("0.0.0.0/0"),
            connection=ec2.Port.tcp(443),
            description="Allow outbound HTTPS traffic through NatGateway",
        )


        # RDS database Ingress rules.
        # Ingress rule from AppInstances.
        self.SG_RDSdb.add_ingress_rule(
            peer=self.SG_AppInstances,
            connection=ec2.Port.tcp(3306),
            description="Allow inbound MySQL traffic from SG_AppInstances",
        )

        # RDS database Egress rules.
        # Egress rule to SG_AppInstances.
        self.SG_RDSdb.add_egress_rule(
            peer=self.SG_AppInstances,
            connection=ec2.Port.tcp(3306),
            description="Allow outbound MySQL traffic to SG_App1",
        )


        # EIC Endpoint Ingress rules.
        # Ingress rule for AWS API calls.
        self.SG_EIC_Endpoint.add_ingress_rule(
            peer=ec2.Peer.ipv4("0.0.0.0/0"),
            connection=ec2.Port.tcp(443),
            description="Allow inbound HTTPS traffic for AWS API calls"
        )
        # Ingress rule from SG_AppInstances.
        self.SG_EIC_Endpoint.add_ingress_rule(
            peer=self.SG_AppInstances,
            connection=ec2.Port.tcp(22),
            description="Allow inbound SSH traffic from SG_AppInstances",
        )
                
        
        # EIC Endpoint Egress rules.
        # Egress rule for AWS API calls.
        self.SG_EIC_Endpoint.add_egress_rule(
            peer=ec2.Peer.ipv4("0.0.0.0/0"),
            connection=ec2.Port.tcp(443),
            description="Allow outbound HTTPS traffic for AWS API calls"
        )
        # Egress rule to SG_AppInstances.
        self.SG_EIC_Endpoint.add_egress_rule(
            peer=self.SG_AppInstances,
            connection=ec2.Port.tcp(22),
            description="Allow outbound SSH traffic to SG_AppInstances",
        )

        
