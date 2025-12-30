import { Construct } from 'constructs';
import * as sns from 'aws-cdk-lib/aws-sns';
import * as subs from 'aws-cdk-lib/aws-sns-subscriptions';
import * as iam from 'aws-cdk-lib/aws-iam';

interface SecurityTopicProps {
    readonly topicName: string;
    readonly alertEmail?: string;
}

/**
 * SNS Topic for centralized security alerts
 */
export class SecurityTopic extends Construct {
    public readonly topic: sns.ITopic;

    constructor(scope: Construct, id: string, props: SecurityTopicProps) {
        super(scope, id);

        const securityTopic = new sns.Topic(this, 'SecurityTopic', {
            topicName: props.topicName,
            displayName: 'Security Hub Automated Alerts',
        });
        
        // Allow EventBridge and Lambda to publish alerts
        securityTopic.addToResourcePolicy(
            new iam.PolicyStatement({
                actions: ['sns:Publish'],
                principals: [
                    new iam.ServicePrincipal('events.amazonaws.com'),
                    new iam.ServicePrincipal(`lambda.amazonaws.com`),
                ],
                resources: [securityTopic.topicArn],
            }),
        );

        // Optional email subscription for security notifications
        if (props.alertEmail) {
            securityTopic.addSubscription(new subs.EmailSubscription(props.alertEmail));
        }

        this.topic = securityTopic;
    }
}