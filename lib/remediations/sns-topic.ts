import { Construct } from 'constructs';
import * as sns from 'aws-cdk-lib/aws-sns';
import * as iam from 'aws-cdk-lib/aws-iam';

interface SecurityTopicProps {
    readonly topicName: string;
}

export class SecurityTopic extends Construct {
    public readonly topic: sns.ITopic;

    constructor(scope: Construct, id: string, props: SecurityTopicProps) {
        super(scope, id);

        const securityTopic = new sns.Topic(this, 'SecurityTopic', {
            topicName: props.topicName,
        });

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

        this.topic = securityTopic;
    }
}