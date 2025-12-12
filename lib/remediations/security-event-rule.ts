import { Construct } from 'constructs';
import * as events from 'aws-cdk-lib/aws-events';
import * as targets from 'aws-cdk-lib/aws-events-targets';
import * as lambda from 'aws-cdk-lib/aws-lambda';

interface SecurityEventRuleProps {
    readonly targetLambda: lambda.IFunction;
    readonly regionTag: string;
}

export class SecurityEventRule extends Construct {
    constructor(scope: Construct, id: string, props: SecurityEventRuleProps) {
        super(scope, id);

        const securityHubRule = new events.Rule(this, `RemediationRule${props.regionTag}`, {
            description: `Lambda Remediation findings EC2 ${props.regionTag}`,
            eventPattern: {
                source: ['aws.securityhub'],
                detailType: ['Security Hub Findings - Imported'],
                detail: {
                    "Workflow": { "Status": ["NEW"] },
                    "Severity": { "Label": ["HIGH", "CRITICAL"] },
                    "Resources": { "Type": ["AwsEc2Instance"] }
                }
            },
        });

        securityHubRule.addTarget(new targets.LambdaFunction(props.targetLambda));
    }
}