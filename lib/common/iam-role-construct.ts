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

        // Core actions for forensics and isolation
        this.role.addToPolicy(new iam.PolicyStatement({
            sid: 'EC2RemediationActions',
            actions: [
                'ec2:StopInstances',
                'ec2:DescribeIamInstanceProfileAssociations',
                'ec2:DisassociateIamInstanceProfile',
                'ec2:DescribeInstances',
                'ec2:ModifyInstanceAttribute',
                'ssm:DescribeSessions',
                'ssm:TerminateSession',
                'iam:PutRolePolicy',
                'iam:GetInstanceProfile',
                'iam:GetRole',
                'ssm:SendCommand',
                'ssm:GetCommandInvocation',
                's3:PutObject'
            ],
            resources: ['*'],
        }));

        // --- UPDATED: SSM PARAMETER STORE PERMISSIONS FOR LOCKING ---
        this.role.addToPolicy(new iam.PolicyStatement({
            sid: 'SSMParameterLockManagement',
            actions: [
                'ssm:GetParameter',
                'ssm:PutParameter',    // Needed to CREATE the lock
                'ssm:DeleteParameter'  // Needed to CLEANUP the lock
            ],
            resources: [
                `arn:aws:ssm:*:*:parameter/security/*`,
                `arn:aws:ssm:*:*:parameter/security/lock/*`
            ],
        }));

        // Permission to update Security Hub finding status
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