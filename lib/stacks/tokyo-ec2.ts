import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as ssm from 'aws-cdk-lib/aws-ssm';

interface TokyoEC2StackProps extends cdk.StackProps {
    readonly regionName: string; 
}

/**
 * Secondary region workload stack for Tokyo.
 * Optimized for secure forensics isolation and automation.
 */
export class TokyoEC2Stack extends cdk.Stack {
    constructor(scope: Construct, id: string, props: TokyoEC2StackProps) {
        super(scope, id, props);

        const regionTag = props.regionName.toUpperCase();

        // 1. Fetch bucket ARN from SSM
        const bucketArn = ssm.StringParameter.valueForStringParameter(
            this, 
            `/security/config-bucket-arn-${props.regionName}`
        );

        // 2. VPC Configuration (10.2.0.0/16 for Tokyo)
        const vpc = new ec2.Vpc(this, `Vpc${regionTag}`, {
            maxAzs: 2, 
            ipAddresses: ec2.IpAddresses.cidr('10.2.0.0/16'),
            vpcName: `${regionTag}-VPC`,
            natGateways: 1, 
        });

        // 3. VPC Endpoints
        vpc.addGatewayEndpoint(`S3Endpoint${regionTag}`, {
            service: ec2.GatewayVpcEndpointAwsService.S3,
        });

        vpc.addInterfaceEndpoint(`SSMEndpoint${regionTag}`, {
            service: ec2.InterfaceVpcEndpointAwsService.SSM,
            privateDnsEnabled: true,
        });

        vpc.addInterfaceEndpoint(`SSMMessagesEndpoint${regionTag}`, {
            service: ec2.InterfaceVpcEndpointAwsService.SSM_MESSAGES,
            privateDnsEnabled: true,
        });

        vpc.addInterfaceEndpoint(`Ec2MessagesEndpoint${regionTag}`, {
            service: ec2.InterfaceVpcEndpointAwsService.EC2_MESSAGES,
            privateDnsEnabled: true,
        });

        // 4. Security Groups
        const instanceSG = new ec2.SecurityGroup(this, `InstanceSG${regionTag}`, {
            vpc: vpc,
            allowAllOutbound: true,
            securityGroupName: `Web-SG-${regionTag}`,
        });
        instanceSG.addIngressRule(ec2.Peer.anyIpv4(), ec2.Port.tcp(22), 'Allow SSH');
        instanceSG.addIngressRule(ec2.Peer.anyIpv4(), ec2.Port.tcp(80), 'Allow HTTP');

        const quarantineSG = new ec2.SecurityGroup(this, `QuarantineSG${regionTag}`, {
            vpc: vpc,
            allowAllOutbound: false,
            securityGroupName: `Quarantine-SG-${regionTag}`,
            description: 'Isolate compromised instances but keep SSM/S3 access via Endpoints',
        });

        quarantineSG.addEgressRule(
            ec2.Peer.ipv4(vpc.vpcCidrBlock), 
            ec2.Port.tcp(443), 
            'Allow HTTPS for internal VPC Endpoints'
        );

        new ssm.StringParameter(this, 'QuarantineSgParam', {
            parameterName: '/security/quarantine-sg-id',
            stringValue: quarantineSG.securityGroupId,
            description: `Quarantine SG ID for ${regionTag}`,
        });

        // 5. IAM Role
        const ec2Role = new iam.Role(this, `EC2SSMRole${regionTag}`, {
            assumedBy: new iam.ServicePrincipal('ec2.amazonaws.com'),
            managedPolicies: [
                iam.ManagedPolicy.fromAwsManagedPolicyName('AmazonSSMManagedInstanceCore'),
            ],
        });
        
        ec2Role.addToPolicy(new iam.PolicyStatement({
            sid: 'AllowForensicsOperations',
            effect: iam.Effect.ALLOW,
            actions: ['s3:PutObject', 's3:GetObject'],
            resources: [
                `${bucketArn}/forensics/*`,
                `${bucketArn}/tools/*`
            ],
        }));

        // 6. EC2 Instance with UserData for AVML
        const ec2Instance = new ec2.Instance(this, `TestInstance${regionTag}`, {
            instanceName: `Victim-EC2-${regionTag}`,
            vpc: vpc,
            instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MICRO),
            machineImage: ec2.MachineImage.latestAmazonLinux2023(),
            securityGroup: instanceSG,
            role: ec2Role,
            vpcSubnets: { subnetType: ec2.SubnetType.PUBLIC },
            associatePublicIpAddress: true,
        });

        // Cập nhật đường dẫn chuẩn /usr/local/bin
        ec2Instance.addUserData(
            'sudo yum update -y',
            'sudo yum install -y wget',
            'sudo wget https://github.com/microsoft/avml/releases/download/v0.14.0/avml -O /usr/local/bin/avml',
            'sudo chmod +x /usr/local/bin/avml'
        );

        // 7. Outputs
        new cdk.CfnOutput(this, `InstanceIdOutput${regionTag}`, { value: ec2Instance.instanceId });
        new cdk.CfnOutput(this, `VpcIdOutput${regionTag}`, { value: vpc.vpcId });
        new cdk.CfnOutput(this, `QuarantineSGIdOutput${regionTag}`, { value: quarantineSG.securityGroupId });
    }
}