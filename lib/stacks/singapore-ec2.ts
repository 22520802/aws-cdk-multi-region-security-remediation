import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as ssm from 'aws-cdk-lib/aws-ssm';

interface SingaporeEC2StackProps extends cdk.StackProps {
    readonly regionName: string; 
}

export class SingaporeEC2Stack extends cdk.Stack {
    constructor(scope: Construct, id: string, props: SingaporeEC2StackProps) {
        super(scope, id, props);

        const regionTag = props.regionName.toUpperCase();

        // 1. VPC 
        const vpc = new ec2.Vpc(this, `Vpc${regionTag}`, {
            maxAzs: 2, 
            cidr: '10.1.0.0/16',
            vpcName: `${regionTag}-VPC`,
            natGateways: 1, 
        });

        // 2. Security Group
        const instanceSG = new ec2.SecurityGroup(this, `InstanceSG${regionTag}`, {
            vpc: vpc,
            allowAllOutbound: true,
            securityGroupName: `Web-SG-${regionTag}`,
        });
        instanceSG.addIngressRule(ec2.Peer.anyIpv4(), ec2.Port.tcp(22), 'Allow SSH access');
        instanceSG.addIngressRule(ec2.Peer.anyIpv4(), ec2.Port.tcp(80), 'Allow HTTP access');

        // 3. QUARANTINE SECURITY GROUP 
        const quarantineSG = new ec2.SecurityGroup(this, `QuarantineSG${regionTag}`, {
            vpc: vpc,
            allowAllOutbound: false, 
            securityGroupName: `Quarantine-SG-${regionTag}`,
            description: 'Security Group used to immediately isolate compromised instances. Denies all traffic.',
        });

        // 4. SSM
        new ssm.StringParameter(this, 'QuarantineSgParam', {
            parameterName: '/security/quarantine-sg-id',
            stringValue: quarantineSG.securityGroupId,
            description: `The ID of the Quarantine Security Group for ${regionTag}`,
        });

        // 5. IAM ROLE EC2
        new iam.Role(this, `EC2SSMRole${regionTag}`, {
            assumedBy: new iam.ServicePrincipal('ec2.amazonaws.com'),
            managedPolicies: [
                iam.ManagedPolicy.fromAwsManagedPolicyName('AmazonSSMManagedInstanceCore'),
            ],
        });
        
        // 6. OUTPUTS
        new cdk.CfnOutput(this, `VpcIdOutput${regionTag}`, {
            value: vpc.vpcId,
            exportName: `${regionTag}-VpcId`, 
        });
        
        new cdk.CfnOutput(this, `QuarantineSGIdOutput${regionTag}`, {
            value: quarantineSG.securityGroupId,
            exportName: `${regionTag}-QuarantineSGId`, 
        });
    }
}