import { Construct } from 'constructs';
import * as events from 'aws-cdk-lib/aws-events';
import * as targets from 'aws-cdk-lib/aws-events-targets';
import * as lambda from 'aws-cdk-lib/aws-lambda';

interface SecurityEventRuleProps {
    readonly targetLambda: lambda.IFunction;
    readonly regionTag: string;
}

/**
 * EventBridge rule to trigger remediation based on Security Hub findings
 */
export class SecurityEventRule extends Construct {
    constructor(scope: Construct, id: string, props: SecurityEventRuleProps) {
        super(scope, id);

        // Rule to capture High and Critical EC2 findings from Security Hub
        const securityHubRule = new events.Rule(this, `RemediationRule${props.regionTag}`, {
            description: `Trigger Lambda remediation for EC2 findings in ${props.regionTag}`,
            eventPattern: {
                source: ['aws.securityhub'],
                detailType: ['Findings Imported V2'],
                detail: {
                    findings: {
                        resources: { type: ["AWS::EC2::Instance"] },
                        severity: ['High', 'Critical'],
                        status: ['New']
                    }
                }
            },
        });

        // Set Lambda as the automated response target
        securityHubRule.addTarget(new targets.LambdaFunction(props.targetLambda));
    }
}