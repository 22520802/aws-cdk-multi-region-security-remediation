import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as securityhub from 'aws-cdk-lib/aws-securityhub';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as path from 'path';

import { ConfigRoleConstruct, RemediationLambdaRoleConstruct } from '../common/iam-role-construct';
import { ConfigModule } from '../constructs/config-module';
import { GuardDutyModule } from '../constructs/guardduty-module';
import { InspectorModule } from '../constructs/inspector-module';
import { SecurityTopic } from '../remediations/sns-topic';
import { SecurityEventRule } from '../remediations/security-event-rule';
import { NodejsFunction } from 'aws-cdk-lib/aws-lambda-nodejs';

/**
 * Primary Security Stack for Singapore acting as the centralized Remediation Hub
 */
export class SingaporeSecurityStack extends cdk.Stack {
    constructor(scope: Construct, id: string, props?: cdk.StackProps) {
        super(scope, id, props);

        const regionTag = 'SINGAPORE';
        const configRole = new ConfigRoleConstruct(this, 'SharedIAM').role; 

        // Central Security Hub instance
        const securityHubResource = new securityhub.CfnHubV2(this, 'SecurityHubSingapore', {
            tags: { Region: 'Singapore' },
        });

        // Core threat detection and configuration modules
        new GuardDutyModule(this, 'GuardDuty', { regionId: 'Singapore' });
        new ConfigModule(this, 'ConfigService', { configRole: configRole, regionId: 'Singapore' });
        new InspectorModule(this, 'Inspector', { regionId: 'Singapore' });

        // Aggregate security findings from Tokyo to Singapore
        const aggregatorResource = new securityhub.CfnAggregatorV2(this, 'CrossRegionAggregator', {
            linkedRegions: ['ap-northeast-1'],
            regionLinkingMode: 'SPECIFIED_REGIONS',
        }); 
        aggregatorResource.addDependency(securityHubResource);

        // Centralized SNS topic for security alerts
        const securityTopic = new SecurityTopic(this, 'SecurityNotification', {
            topicName: `Security-Alerts-${regionTag}`,
            alertEmail: 'jisan33351@emaxasp.com',
        });

        // Lambda function for automated forensics and instance isolation
        const remediationRoleConstruct = new RemediationLambdaRoleConstruct(this, 'RemediationIAM');
        
        const remediationLambda = new NodejsFunction(this, 'QuarantineLambda', {
            entry: path.join(__dirname, '../../lib/remediations/quarantine-handler.ts'),
            handler: 'handler',
            runtime: lambda.Runtime.NODEJS_20_X,
            memorySize: 512,
            role: remediationRoleConstruct.role,
            timeout: cdk.Duration.minutes(10),
            environment: {
                'SNS_TOPIC_ARN': securityTopic.topic.topicArn,
            },
        });
        securityTopic.topic.grantPublish(remediationLambda);

        // EventBridge rule to trigger remediation based on aggregated findings
        new SecurityEventRule(this, 'RemediationTrigger', {
            targetLambda: remediationLambda, 
            regionTag: regionTag,
        });
    }
}