import aws_cdk as core
import aws_cdk.assertions as assertions

from multi_tier_architecture.multi_tier_architecture_stack import MultiTierArchitectureStack

# example tests. To run these tests, uncomment this file along with the example
# resource in multi_tier_architecture/multi_tier_architecture_stack.py
def test_sqs_queue_created():
    app = core.App()
    stack = MultiTierArchitectureStack(app, "multi-tier-architecture")
    template = assertions.Template.from_stack(stack)

#     template.has_resource_properties("AWS::SQS::Queue", {
#         "VisibilityTimeout": 300
#     })
