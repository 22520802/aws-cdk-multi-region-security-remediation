// D:\SHMR\lib\common\iam-role-construct.ts
import { Construct } from 'constructs';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as cdk from 'aws-cdk-lib';

export class ConfigRoleConstruct extends Construct {
    public readonly role: iam.IRole;
    constructor(scope: Construct, id: string) {
        super(scope, id);

        const region = cdk.Stack.of(this).region.toUpperCase();

        this.role = new iam.Role(this, 'ConfigServiceRole', {
            roleName: `Shared-Security-Config-Role-${region}`,
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
            roleName: `Remediation-Lambda-Role-${region}`,
            assumedBy: new iam.ServicePrincipal('lambda.amazonaws.com'),
        });

        this.role.addManagedPolicy(
            iam.ManagedPolicy.fromAwsManagedPolicyName('service-role/AWSLambdaBasicExecutionRole')
        );

        this.role.addToPolicy(new iam.PolicyStatement({
            sid: 'EC2RemediationActions',
            actions: [
                'ec2:DescribeInstances',
                'ec2:DescribeVolumes',
                'ec2:DescribeIamInstanceProfileAssociations',
                'ec2:ModifyInstanceAttribute',        // Cách ly SG (Quarantine network)
                'ec2:CreateSnapshot',                 // Tạo forensic EBS snapshots
                'ec2:DisassociateIamInstanceProfile', // Gỡ IAM roles
                'ec2:StopInstances'                   // Tắt instance
            ],
            resources: ['*'],
        }));

        this.role.addToPolicy(new iam.PolicyStatement({
            sid: 'SSMSessionManagement',
            actions: [
                'ssm:DescribeSessions',
                'ssm:TerminateSession'
            ],
            resources: ['*'],
        }));

        this.role.addToPolicy(new iam.PolicyStatement({
            sid: 'SecurityHubUpdate',
            actions: [
                'securityhub:BatchUpdateFindings',
                'securityhub:GetFindings'
            ],
            resources: ['*'],
        }));
    }
}