import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as iam from 'aws-cdk-lib/aws-iam';

interface SingaporeEC2StackProps extends cdk.StackProps {
    readonly regionName: string; 
}

export class SingaporeEC2Stack extends cdk.Stack {
    constructor(scope: Construct, id: string, props: SingaporeEC2StackProps) {
        super(scope, id, props);

        const regionTag = props.regionName.toUpperCase();
        const keyPairName = 'key-singapore';

        // 1. Tạo VPC
        const vpc = new ec2.Vpc(this, `Vpc${regionTag}`, {
            maxAzs: 2, 
            cidr: '10.1.0.0/16',
            vpcName: `${regionTag}-VPC`,
            natGateways: 1, 
        });

        // 2. Định nghĩa Security Group cơ bản (cho phép SSH và HTTP)
        const instanceSG = new ec2.SecurityGroup(this, `InstanceSG${regionTag}`, {
            vpc: vpc,
            allowAllOutbound: true,
            securityGroupName: `Web-SG-${regionTag}`,
        });

        instanceSG.addIngressRule(ec2.Peer.anyIpv4(), ec2.Port.tcp(22), 'Allow SSH access');
        instanceSG.addIngressRule(ec2.Peer.anyIpv4(), ec2.Port.tcp(80), 'Allow HTTP access');


        // 3. TẠO QUARANTINE SECURITY GROUP (SG Cách ly)
        const quarantineSG = new ec2.SecurityGroup(this, `QuarantineSG${regionTag}`, {
            vpc: vpc,
            // Deny All Outbound
            allowAllOutbound: false, 
            securityGroupName: `Quarantine-SG-${regionTag}`,
            description: 'Security Group used to immediately isolate compromised instances. Denies all traffic.',
        });


        // --- MỚI: Tạo IAM Role cho EC2 để dùng SSM ---
        const ec2Role = new iam.Role(this, `EC2SSMRole${regionTag}`, {
            assumedBy: new iam.ServicePrincipal('ec2.amazonaws.com'),
            managedPolicies: [
                iam.ManagedPolicy.fromAwsManagedPolicyName('AmazonSSMManagedInstanceCore'),
            ],
        });


        // // 4. Tạo 3 EC2 Instances (Ví dụ đã bật lại)
        // const machineImage = ec2.MachineImage.latestAmazonLinux2023();

        // for (let i = 1; i <= 3; i++) {
        //     new ec2.Instance(this, `Instance${i}${regionTag}`, {
        //         vpc: vpc,
        //         vpcSubnets: { subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS }, // Nên đặt instance ở Private Subnet an toàn hơn
        //         instanceType: ec2.InstanceType.of(ec2.InstanceClass.T2, ec2.InstanceSize.MICRO),
        //         machineImage: machineImage,
        //         // keyName: keyPairName, // Bỏ keypair
        //         role: ec2Role, // Gán role SSM
        //         securityGroup: instanceSG,
        //         tags: [
        //             { key: 'Name', value: `App-Server-${i}-${regionTag}` },
        //             { key: 'Security', value: 'Enabled' },
        //         ]
        //     });
        // }
        
        // 5. Xuất VPC ID và Quarantine SG ID
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