import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as config from 'aws-cdk-lib/aws-config';
import * as ssm from 'aws-cdk-lib/aws-ssm';

interface ConfigModuleProps {
  configRole: iam.IRole; 
  regionId: string; 
}

/**
 * Setup AWS Config and centralized S3 storage for logs and forensics
 */
export class ConfigModule extends Construct {
  public readonly bucket: s3.Bucket;

  constructor(scope: Construct, id: string, props: ConfigModuleProps) {
    super(scope, id);

    const regionTag = props.regionId.toUpperCase();
    const accountId = cdk.Stack.of(this).account;

    // S3 Bucket for AWS Config logs and Forensic RAM dumps
    this.bucket = new s3.Bucket(this, `ConfigBucket${regionTag}`, {
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      encryption: s3.BucketEncryption.S3_MANAGED,
      enforceSSL: true,
      versioned: true,
      removalPolicy: cdk.RemovalPolicy.RETAIN,
      autoDeleteObjects: false,
    });

    // Store bucket name in SSM for automated remediation discovery
    new ssm.StringParameter(this, `ForensicsBucketParam${regionTag}`, {
      parameterName: `/security/forensics-bucket-name`,
      stringValue: this.bucket.bucketName,
      description: `Target S3 bucket for forensics and Config logs in ${props.regionId}`,
    });

    // Grant AWS Config service role permissions to write to the bucket
    props.configRole.addToPrincipalPolicy(
        new iam.PolicyStatement({
            effect: iam.Effect.ALLOW,
            actions: ['s3:PutObject', 's3:GetBucketAcl'],
            resources: [
                this.bucket.bucketArn,
                `${this.bucket.bucketArn}/*`
            ],
        })
    );
    
    // Resource policy to allow AWS Config to check bucket status
    this.bucket.addToResourcePolicy(
      new iam.PolicyStatement({
        effect: iam.Effect.ALLOW,
        actions: ['s3:GetBucketAcl', 's3:ListBucket'],
        resources: [this.bucket.bucketArn],
        principals: [new iam.ServicePrincipal('config.amazonaws.com')],
        conditions: {
          StringEquals: { 'AWS:SourceAccount': accountId },
        },
      })
    );
    
    // Resource policy to allow AWS Config to deliver log files
    this.bucket.addToResourcePolicy(
      new iam.PolicyStatement({
        effect: iam.Effect.ALLOW,
        actions: ['s3:PutObject'],
        resources: [
            `${this.bucket.bucketArn}/AWSLogs/${accountId}/Config/*`, 
            `${this.bucket.bucketArn}/aws-config/AWSLogs/${accountId}/Config/*`, 
        ],
        principals: [new iam.ServicePrincipal('config.amazonaws.com')],
        conditions: {
          StringEquals: {
            's3:x-amz-acl': 'bucket-owner-full-control',
            'AWS:SourceAccount': accountId,
          },
        },
      })
    );

    // Delivery Channel to define data delivery destination
    const deliveryChannel = new config.CfnDeliveryChannel(this, `DeliveryChannel${regionTag}`, {
      s3BucketName: this.bucket.bucketName,
      s3KeyPrefix: 'aws-config',
      configSnapshotDeliveryProperties: {
        deliveryFrequency: 'One_Hour',
      },
    });
    deliveryChannel.node.addDependency(this.bucket);

    // Configuration Recorder to track resource changes
    const recorder = new config.CfnConfigurationRecorder(this, `Recorder${regionTag}`, {
      roleArn: props.configRole.roleArn,
      recordingGroup: {
        allSupported: true,
        includeGlobalResourceTypes: true,
      },
    });
    recorder.node.addDependency(props.configRole);

    // Output bucket ARN for cross-stack reference
    new cdk.CfnOutput(this, `ConfigBucketArn${regionTag}`, {
        value: this.bucket.bucketArn,
        exportName: `ConfigBucketArn-${props.regionId}`,
    });
  }
}