import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as securityhub from 'aws-cdk-lib/aws-securityhub';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as iam from 'aws-cdk-lib/aws-iam';

import { ConfigRoleConstruct, RemediationLambdaRoleConstruct } from '../common/iam-role-construct';import { ConfigModule } from '../constructs/config-module';
import { GuardDutyModule } from '../constructs/guardduty-module';
import { InspectorModule } from '../constructs/inspector-module';
import { SecurityTopic } from '../remediations/sns-topic';
import { SecurityEventRule } from '../remediations/security-event-rule';


export class SingaporeSecurityStack extends cdk.Stack {
    constructor(scope: Construct, id: string, props?: cdk.StackProps) {
        super(scope, id, props);

        const regionTag = 'SINGAPORE';
        const configRole = new ConfigRoleConstruct(this, 'SharedIAM').role; 
        const quarantineSGId = cdk.Fn.importValue(`${regionTag}-QuarantineSGId`);

        // 1. Security Hub
        new securityhub.CfnHubV2(this, 'SecurityHubSingapore', { tags: { Region: 'Singapore', }, });

        // 2. GuardDuty
        new GuardDutyModule(this, 'GD', { regionId: 'Singapore' });

        // 3. Config
        new ConfigModule(this, 'ConfigService', { configRole: configRole, regionId: 'Singapore' });

        // 4. Inspector
        new InspectorModule(this, 'Inspector', { regionId: 'Singapore' });

        //5. Aggregator

        // new securityhub.CfnAggregatorV2(this, 'CrossRegionAggregator', {
        //     linkedRegions: ['ap-northeast-1'],
        //     regionLinkingMode: 'SPECIFIED_REGIONS',
        //     tags: {
        //         Region: 'Singapore',
        //     },
        // }); 

        // new securityhub.CfnFindingAggregator(this, 'CrossRegionAggregator', {
        //     regionLinkingMode: 'SPECIFIED_REGIONS',
        //     regions: ['ap-northeast-1'],
        // }); 

        // 6. SNS TOPIC
        const securityTopic = new SecurityTopic(this, 'SecurityNotification', {
            topicName: `Security-Alerts-${regionTag}`,
        });

        // 7. Lambda
        const remediationRoleConstruct = new RemediationLambdaRoleConstruct(this, 'RemediationIAM');
        const remediationRole = remediationRoleConstruct.role;

        securityTopic.topic.grantPublish(remediationRole);

        const remediationLambda = new lambda.Function(this, 'QuarantineLambda', {
            runtime: lambda.Runtime.NODEJS_20_X, 
            code: lambda.Code.fromAsset('lib/remediations'), 
            handler: 'quarantine-handler.handler', // Tên file code Lambda
            role: remediationRole,
            timeout: cdk.Duration.minutes(2),
            environment: {
                QUARANTINE_SG_ID: quarantineSGId,
                SNS_TOPIC_ARN: securityTopic.topic.topicArn,
            },
        });
        
        // 8. EVENTBRIDGE RULE
        new SecurityEventRule(this, 'RemediationTrigger', {
            targetLambda: remediationLambda, 
            regionTag: regionTag,
        });

        // 9. EXPORT SNS TOPIC ARN
        new cdk.CfnOutput(this, `SnsTopicArnOutput${regionTag}`, {
            value: securityTopic.topic.topicArn,
            exportName: `${regionTag}-SecuritySnsTopicArn`, 
        });
    }
}