import { Construct } from 'constructs';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as cdk from 'aws-cdk-lib';

/**
 * Role for AWS Config service to record resource changes
 */
export class ConfigRoleConstruct extends Construct {
    public readonly role: iam.IRole;

    constructor(scope: Construct, id: string) {
        super(scope, id);
        
        this.role = new iam.Role(this, 'ConfigServiceRole', {
            assumedBy: new iam.ServicePrincipal('config.amazonaws.com'),
            managedPolicies: [
                iam.ManagedPolicy.fromAwsManagedPolicyName('service-role/AWS_ConfigRole'),
            ],
        });
    }
}

/**
 * Role for Lambda functions to perform automated forensics and isolation
 */
export class RemediationLambdaRoleConstruct extends Construct {
    public readonly role: iam.Role;

    constructor(scope: Construct, id: string) {
        super(scope, id);

        this.role = new iam.Role(this, 'LambdaRole', {
            assumedBy: new iam.ServicePrincipal('lambda.amazonaws.com'),
            description: 'Role for Security Remediation Lambda to isolate EC2 and capture RAM',
        });

        // Basic CloudWatch logging permissions
        this.role.addManagedPolicy(
            iam.ManagedPolicy.fromAwsManagedPolicyName('service-role/AWSLambdaBasicExecutionRole')
        );

        // Core actions for forensics and isolation: EC2 management, SSM commands, and RAM dump upload
        this.role.addToPolicy(new iam.PolicyStatement({
            sid: 'EC2RemediationActions',
            actions: [
                'ec2:DescribeInstances',
                'ec2:ModifyInstanceAttribute', // Used for Security Group swapping
                'ssm:DescribeSessions',
                'ssm:TerminateSession',       // Used to kick active attackers
                'iam:PutRolePolicy',          // Used to attach Deny policies
                'iam:GetInstanceProfile',
                'iam:GetRole',
                'ssm:SendCommand',            // Runs AVML on target instance
                'ssm:GetCommandInvocation',
                'ssm:GetParameter',
                's3:PutObject'                // Uploads RAM dump to forensics bucket
            ],
            resources: ['*'],
        }));

        // Permission to retrieve the specific Quarantine Security Group ID
        this.role.addToPolicy(new iam.PolicyStatement({
            sid: 'SSMReadParameter',
            actions: ['ssm:GetParameter'],
            resources: [`arn:aws:ssm:*:*:parameter/security/quarantine-sg-id`],
        }));

        // Permission to update Security Hub finding status to RESOLVED
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