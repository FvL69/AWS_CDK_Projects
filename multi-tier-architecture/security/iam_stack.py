from aws_cdk import (
    NestedStack,
    aws_ec2 as ec2,
    aws_iam as iam,
    aws_rds as rds,
)
from constructs import Construct

class IamStack(NestedStack):

    def __init__(self, scope:Construct, id:str,
                 vpc: ec2.Vpc,
                 eic_endpoint: ec2.CfnInstanceConnectEndpoint,
                 rds_db: rds.DatabaseInstance,
                 admin_key_pair: str,
                 **kwargs) -> None:
        super().__init__(scope, id, **kwargs)


        ### IAM GROUP-OF-USERS  ###

        self.AdminGroup = iam.Group(
            self, "AdminGroup",
            group_name="AdminGroup",
        )

        self.DatabaseGroup = iam.Group(
            self, "DatabaseGroup",  
            group_name="DatabaseGroup"          
        )


        ###  IAM POLICIES  ###

        # Create an EIC Endpoint IAM policy for AdminGroup.

        # Set variable eic_subnet_id for EICEndpointPolicy resources arn value.
        eic_subnet_id = vpc.select_subnets(
                availability_zones=[vpc.availability_zones[0]],
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

        # Adding additional permissions to instantiate EIC Endpoint connection.
        self.EIC_Endpoint_Policy.add_statements(
            iam.PolicyStatement(
                sid="EC2InstanceConnect",
                actions=["ec2-instance-connect:openTunnel"],
                effect=iam.Effect.ALLOW,
                resources=[f"arn:aws:ec2:{self.region}:{self.account}:instance-connect-endpoint/{eic_endpoint.attr_id}"],
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

        # Attach Endpoint policy to AdminGroup.
        self.EIC_Endpoint_Policy.attach_to_group(self.AdminGroup)



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
                    resources=[f"arn:aws:ec2:{self.region}:{self.account}:key-pair/{admin_key_pair}"],
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
                        f"arn:aws:rds-db:{self.region}:{self.account}:dbuser:{rds_db.instance_identifier}/*"
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

        # Attach policy to DatabaseGroup.  
        self.RDSReadOnlyPolicy.attach_to_group(self.DatabaseGroup)



