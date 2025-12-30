import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as ssm from 'aws-cdk-lib/aws-ssm';

interface TokyoEC2StackProps extends cdk.StackProps {
    readonly regionName: string; 
}

/**
 * Secondary region workload stack for Tokyo
 */
export class TokyoEC2Stack extends cdk.Stack {
    constructor(scope: Construct, id: string, props: TokyoEC2StackProps) {
        super(scope, id, props);

        const regionTag = props.regionName.toUpperCase();

        // Import forensics bucket ARN exported from Tokyo ConfigModule
        const bucketArn = cdk.Fn.importValue(`ConfigBucketArn-${props.regionName}`);

        // VPC with 10.2.0.0/16 CIDR to avoid overlap with Singapore
        const vpc = new ec2.Vpc(this, `Vpc${regionTag}`, {
            maxAzs: 2, 
            ipAddresses: ec2.IpAddresses.cidr('10.2.0.0/16'),
            vpcName: `${regionTag}-VPC`,
            natGateways: 1, 
        });

        // vpc.addInterfaceEndpoint(`SSMEndpoint${regionTag}`, {
        //     service: ec2.InterfaceVpcEndpointAwsService.SSM,
        // });
        // vpc.addInterfaceEndpoint(`SSMMessagesEndpoint${regionTag}`, {
        //     service: ec2.InterfaceVpcEndpointAwsService.SSM_MESSAGES,
        // });
        // vpc.addGatewayEndpoint(`S3Endpoint${regionTag}`, {
        //     service: ec2.GatewayVpcEndpointAwsService.S3,
        // });

        // Default Security Group for web access
        const instanceSG = new ec2.SecurityGroup(this, `InstanceSG${regionTag}`, {
            vpc: vpc,
            allowAllOutbound: true,
            securityGroupName: `Web-SG-${regionTag}`,
        });
        instanceSG.addIngressRule(ec2.Peer.anyIpv4(), ec2.Port.tcp(22), 'Allow SSH');
        instanceSG.addIngressRule(ec2.Peer.anyIpv4(), ec2.Port.tcp(80), 'Allow HTTP');

        // Isolation Security Group for compromised resources
        const quarantineSG = new ec2.SecurityGroup(this, `QuarantineSG${regionTag}`, {
            vpc: vpc,
            allowAllOutbound: false,
            securityGroupName: `Quarantine-SG-${regionTag}`,
            description: 'Isolate compromised instances',
        });

        // Permit internal HTTPS traffic for forensics tools and SSM
        quarantineSG.addEgressRule(
            ec2.Peer.ipv4(vpc.vpcCidrBlock), 
            ec2.Port.tcp(443), 
            'Allow internal HTTPS for SSM and S3'
        );

        // Store Quarantine SG ID in SSM for local remediation discovery
        new ssm.StringParameter(this, 'QuarantineSgParam', {
            parameterName: '/security/quarantine-sg-id',
            stringValue: quarantineSG.securityGroupId,
            description: `Quarantine SG ID for ${regionTag}`,
        });

        // IAM Role for EC2 managed by SSM
        const ec2Role = new iam.Role(this, `EC2SSMRole${regionTag}`, {
            assumedBy: new iam.ServicePrincipal('ec2.amazonaws.com'),
            managedPolicies: [
                iam.ManagedPolicy.fromAwsManagedPolicyName('AmazonSSMManagedInstanceCore'),
            ],
        });
        
        // Grant permissions for forensics data upload and tool access
        ec2Role.addToPolicy(new iam.PolicyStatement({
            sid: 'AllowForensicsOperations',
            effect: iam.Effect.ALLOW,
            actions: [
                's3:PutObject', 
                's3:GetObject'
            ],
            resources: [
                `${bucketArn}/forensics/*`,
                `${bucketArn}/tools/*`
            ],
        }));

        // Test EC2 instance acting as remediation target
        const ec2Instance = new ec2.Instance(this, `TestInstance${regionTag}`, {
            instanceName: `Victim-EC2-${regionTag}`,
            vpc: vpc,
            instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MICRO),
            machineImage: ec2.MachineImage.latestAmazonLinux2023(),
            securityGroup: instanceSG,
            role: ec2Role,
            vpcSubnets: {
                subnetType: ec2.SubnetType.PUBLIC,
            },
            associatePublicIpAddress: true,
        });

        // Stack Outputs for resource tracking
        new cdk.CfnOutput(this, `InstanceIdOutput${regionTag}`, {
            value: ec2Instance.instanceId,
        });

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