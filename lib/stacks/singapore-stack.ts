import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as securityhub from 'aws-cdk-lib/aws-securityhub';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as path from 'path';
import { NodejsFunction } from 'aws-cdk-lib/aws-lambda-nodejs';

import { ConfigRoleConstruct, RemediationLambdaRoleConstruct } from '../common/iam-role-construct';
import { ConfigModule } from '../constructs/config-module';
import { GuardDutyModule } from '../constructs/guardduty-module';
import { InspectorModule } from '../constructs/inspector-module';
import { SecurityTopic } from '../remediations/sns-topic';
import { SecurityEventRule } from '../remediations/security-event-rule';

/**
 * Main security hub for Singapore acting as remediation center.
 */
export class SingaporeSecurityStack extends cdk.Stack {
    constructor(scope: Construct, id: string, props?: cdk.StackProps) {
        super(scope, id, props);

        const regionTag = 'SINGAPORE';
        const configRole = new ConfigRoleConstruct(this, 'SharedIAM').role;
        const signingSecret = 'MySuperSecretKey_SHMR_2025'; // TODO: Use Secrets Manager in production

        // 1. Initialize Central Security Hub
        const securityHubResource = new securityhub.CfnHubV2(this, 'SecurityHubSingapore', {
            tags: { Region: 'Singapore' },
        });

        // 2. Initialize Threat Detection Modules
        new GuardDutyModule(this, 'GuardDuty', { regionId: 'Singapore' });
        new ConfigModule(this, 'ConfigService', { configRole: configRole, regionId: 'Singapore' });
        new InspectorModule(this, 'Inspector', { regionId: 'Singapore' });

        // 3. Cross-Region Aggregation (Link Tokyo)
        const aggregatorResource = new securityhub.CfnAggregatorV2(this, 'CrossRegionAggregator', {
            linkedRegions: ['ap-northeast-1'],
            regionLinkingMode: 'SPECIFIED_REGIONS',
        });
        aggregatorResource.addDependency(securityHubResource);

        // 4. Notifications & IAM Setup
        const securityTopic = new SecurityTopic(this, 'SecurityNotification', {
            topicName: `Security-Alerts-${regionTag}`,
            alertEmail: 'LoiTT14@fpt.com',
        });
        const remediationRoleConstruct = new RemediationLambdaRoleConstruct(this, 'RemediationIAM');

        // 5. Approval Lambda (Human interaction)
        const approvalLambda = new NodejsFunction(this, 'ApprovalLambda', {
            entry: path.join(__dirname, '../../lib/remediations/approval-handler.ts'),
            handler: 'handler',
            runtime: lambda.Runtime.NODEJS_20_X,
            environment: { 'SIGNING_SECRET': signingSecret }
        });

        approvalLambda.addToRolePolicy(new iam.PolicyStatement({
            actions: ['ec2:StopInstances', 'ec2:DescribeInstances', 'ssm:DeleteParameter'],
            resources: ['*'], // Scope down in production
        }));

        const approvalUrl = approvalLambda.addFunctionUrl({
            authType: lambda.FunctionUrlAuthType.NONE,
        });

        // 6. Remediation Lambda (Forensics & Isolation)
        const remediationLambda = new NodejsFunction(this, 'QuarantineLambda', {
            entry: path.join(__dirname, '../../lib/remediations/quarantine-handler.ts'),
            handler: 'handler',
            runtime: lambda.Runtime.NODEJS_20_X,
            memorySize: 512,
            role: remediationRoleConstruct.role,
            timeout: cdk.Duration.minutes(15),
            environment: {
                'SNS_TOPIC_ARN': securityTopic.topic.topicArn,
                'APPROVAL_URL_BASE': approvalUrl.url,
                'SIGNING_SECRET': signingSecret,
            },
        });
        securityTopic.topic.grantPublish(remediationLambda);

        // 7. EventBridge Rule to trigger remediation
        new SecurityEventRule(this, 'RemediationTrigger', {
            targetLambda: remediationLambda,
            regionTag: regionTag,
        });
    }
}