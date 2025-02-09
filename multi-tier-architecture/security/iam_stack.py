from aws_cdk import (
    NestedStack,
    aws_ec2 as ec2,
    aws_iam as iam,
)
from constructs import Construct
from multi_tier_architecture.multi_tier_architecture_stack import MultiTierArchitectureStack


class IamStack(NestedStack):
    def __init__(self, scope:Construct, id:str, **kwargs) -> None:
        super().__init__(scope, id, **kwargs)

        # Parent Stack reference.
        FromMainStack = MultiTierArchitectureStack(self, "Multi_tier_architecture_Stack")


        # Create an EIC Endpoint IAM policy and an AdminGroup to attach the IAM policy to.
        # Any work force users would be added to the AdminGroup manually in the console.

        # Set variable eic_subnet_id for PolicyStatement resource arn.
        eic_subnet_id = FromMainStack.vpc.select_subnets(
                availability_zones=[FromMainStack.vpc.availability_zones[0]],
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
                resources=[f"arn:aws:ec2:{self.region}:{self.account}:instance-connect-endpoint/{FromMainStack.EIC_Endpoint.attr_id}"],
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

        # Create an IAM Group-of-Users for administrative team members.
        self.AdminGroup = iam.Group(
            self, "AdminGroup",
            group_name="AdminGroup",
        )

        # Attach Endpoint policy to AdminGroup.
        self.EIC_Endpoint_Policy.attach_to_group(self.AdminGroup)



        ###  IAM lAUNCH TEMPLATE POLICY  ###

        # Create launch template policy.
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
                    resources=[f"arn:aws:ec2:{self.region}:{self.account}:key-pair/{FromMainStack.AdminKeyPair.key_pair_name}"],
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



        ###  IAM DATABASE POLICY  ###

        # IAM policy 'ReadOnlyAccess' for DatabaseGroup.
        self.RDSReadOnlyPolicy = iam.Policy(
            self, "RDSReadOnlyPolicy",
            statements=[
                iam.PolicyStatement(
                    sid="AllowConnect",
                    actions=[
                        "rds-db:connect",
                    ],
                    effect=iam.Effect.ALLOW,
                    resources=[
                        f"arn:aws:rds-db:{self.region}:{self.account}:dbuser:{FromMainStack.RDSdb.instance_identifier}/*"
                    ],
                ),
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

        # Create an IAM Group_of_Users for DB team members.
        self.DB_Group = iam.Group(
            self, "DatabaseGroup",  
            group_name="DatabaseGroup"          
        )

        # Attach policy to DatabaseGroup.  
        self.RDSReadOnlyPolicy.attach_to_group(self.DB_Group)


