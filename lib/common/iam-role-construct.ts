import { Construct } from 'constructs';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as cdk from 'aws-cdk-lib';

export class ConfigRoleConstruct extends Construct {
    public readonly role: iam.IRole;
    constructor(scope: Construct, id: string) {
        super(scope, id);
        const region = cdk.Stack.of(this).region.toUpperCase();
        this.role = new iam.Role(this, 'ConfigServiceRole', {
            assumedBy: new iam.ServicePrincipal('config.amazonaws.com'),
            managedPolicies: [
                iam.ManagedPolicy.fromAwsManagedPolicyName('service-role/AWS_ConfigRole'),
            ],
        });
    }
}

export class RemediationLambdaRoleConstruct extends Construct {
    public readonly role: iam.Role;

    constructor(scope: Construct, id: string) {
        super(scope, id);
        const region = cdk.Stack.of(this).region.toUpperCase();

        this.role = new iam.Role(this, 'LambdaRole', {
            assumedBy: new iam.ServicePrincipal('lambda.amazonaws.com'),
        });

        this.role.addManagedPolicy(
            iam.ManagedPolicy.fromAwsManagedPolicyName('service-role/AWSLambdaBasicExecutionRole')
        );

        this.role.addToPolicy(new iam.PolicyStatement({
            sid: 'EC2RemediationActions',
            actions: [
                'ec2:DescribeInstances',
                'ec2:ModifyInstanceAttribute',
                'ssm:DescribeSessions',
                'ssm:TerminateSession',
                'iam:PutRolePolicy',
                'iam:GetInstanceProfile',
                'iam:GetRole'                
            ],
            resources: ['*'],
        }));

        this.role.addToPolicy(new iam.PolicyStatement({
            sid: 'SSMReadParameter',
            actions: ['ssm:GetParameter'],
            resources: [`arn:aws:ssm:*:*:parameter/security/quarantine-sg-id`],
        }));

        this.role.addToPolicy(new iam.PolicyStatement({
            sid: 'SecurityHubUpdate',
            actions: [
                'securityhub:BatchUpdateFindings',
                'securityhub:BatchUpdateFindingsV2',
                'securityhub:GetFindings'
            ],
            resources: ['*'],
        }));
    }
}