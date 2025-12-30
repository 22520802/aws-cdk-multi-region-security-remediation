import { PublishCommand, SNSClient } from '@aws-sdk/client-sns';
import { SecurityHubClient, BatchUpdateFindingsV2Command } from '@aws-sdk/client-securityhub';
import { EC2Client, ModifyInstanceAttributeCommand, DescribeInstancesCommand } from '@aws-sdk/client-ec2';
import { IAMClient, PutRolePolicyCommand, GetInstanceProfileCommand } from '@aws-sdk/client-iam';
import { 
    SSMClient, 
    GetParameterCommand, 
    TerminateSessionCommand, 
    DescribeSessionsCommand, 
    SendCommandCommand, 
    GetCommandInvocationCommand,
    GetCommandInvocationCommandOutput 
} from '@aws-sdk/client-ssm';

const SNS_TOPIC_ARN = process.env.SNS_TOPIC_ARN;
const snsClient = new SNSClient({});
const securityHubClient = new SecurityHubClient({});

export const handler = async (event: any): Promise<void> => {
    try {
        const findings = event.detail.findings;
        if (!findings || findings.length === 0) return;

        const ocsfIdentifiers: any[] = [];
        let remediationLog = "";

        for (const finding of findings) {
            const region = finding.cloud?.region || "ap-southeast-1";
            const ssmClient = new SSMClient({ region });
            
            if (finding.resources && Array.isArray(finding.resources)) {
                for (const resource of finding.resources) {
                    const resourceId = resource.uid;
                    const resourceType = resource.type;

                    if (resourceType === 'AWS::EC2::Instance' && resourceId) {
                        console.log(`Remediation start: ${resourceId} in ${region}`);

                        const getParam = await ssmClient.send(new GetParameterCommand({ 
                            Name: '/security/forensics-bucket-name' 
                        }));
                        const bucketName = getParam.Parameter?.Value;

                        if (!bucketName) {
                            console.error(`Skip: Bucket name missing for ${region}`);
                            continue;
                        }

                        // Execute memory forensics
                        await runForensicsWorkflow(resourceId, region, bucketName);

                        // Execute network isolation
                        await quarantineNetwork(resourceId, region);

                        // Cleanup sessions and revoke permissions
                        const ssmCount = await terminateSSMSessions(resourceId, region);
                        await revokeIAMForInstance(resourceId, region);

                        remediationLog += `- Success: ${resourceId}\n  + Memory Dump: Captured\n  + Security: Isolated\n  + Sessions: ${ssmCount} terminated\n`;
                    }
                }
            }

            ocsfIdentifiers.push({
                CloudAccountUid: finding.cloud?.account?.uid,
                FindingInfoUid: finding.finding_info?.uid,
                MetadataProductUid: finding.metadata?.product?.uid,
            });
        }

        if (remediationLog) {
            await snsClient.send(new PublishCommand({
                TopicArn: SNS_TOPIC_ARN,
                Subject: `Security Remediation Completed`,
                Message: `Details:\n${remediationLog}`,
            }));

            await securityHubClient.send(new BatchUpdateFindingsV2Command({
                FindingIdentifiers: ocsfIdentifiers,
                Comment: "Automated remediation: Forensics captured and network isolated",
                StatusId: 2,
            }));
        }

    } catch (error) {
        console.error('Fatal error:', error);
        throw error;
    }
};

/**
 * Forensics workflow: Download AVML, dump memory, and upload to S3
 */
async function runForensicsWorkflow(instanceId: string, region: string, bucketName: string) {
    const ssmClient = new SSMClient({ region });

    const forensicsScript = [
        "set -e",
        "echo 'Downloading AVML'",
        "sudo curl -sL -o /usr/local/bin/avml https://github.com/microsoft/avml/releases/download/v0.14.0/avml",
        "sudo chmod +x /usr/local/bin/avml",
        
        "echo 'Capturing memory'",
        "sudo mkdir -p /data-forensics && cd /data-forensics",
        "sudo /usr/local/bin/avml --source /proc/kcore --compress mem.raw.xz || sudo /usr/local/bin/avml --compress mem.raw.xz",
        
        "echo 'Uploading to S3'",
        "if ! command -v aws &> /dev/null; then sudo yum install -y aws-cli || sudo apt-get install -y awscli; fi",
        `sudo aws s3 cp mem.raw.xz s3://${bucketName}/forensics/${instanceId}/$(date +%Y%m%d_%H%M%S)_mem.raw.xz`,
        
        "echo 'Cleaning local files'",
        "cd / && sudo rm -rf /data-forensics"
    ];

    console.log(`Executing forensics: ${instanceId}`);
    const ssmResponse = await ssmClient.send(new SendCommandCommand({
        InstanceIds: [instanceId],
        DocumentName: "AWS-RunShellScript",
        Parameters: { commands: forensicsScript }
    }));

    const commandId = ssmResponse.Command?.CommandId;
    if (!commandId) throw new Error("SSM CommandId missing");

    let status = 'Pending';
    while (status === 'Pending' || status === 'InProgress') {
        await new Promise(r => setTimeout(r, 7000));
        const inv = await ssmClient.send(new GetCommandInvocationCommand({ CommandId: commandId, InstanceId: instanceId }));
        status = inv.Status || 'Failed';
        if (status === 'Failed') {
            console.error(`SSM Error: ${inv.StandardErrorContent}`);
            throw new Error(`Forensics failed: ${inv.StandardErrorContent}`);
        }
    }
    console.log(`Forensics upload success`);
}

/**
 * Network isolation by swapping Security Groups
 */
async function quarantineNetwork(instanceId: string, region: string) {
    const ssmClient = new SSMClient({ region });
    const ec2Client = new EC2Client({ region });

    console.log(`Isolating network: ${instanceId}`);

    const getParam = await ssmClient.send(new GetParameterCommand({ 
        Name: '/security/quarantine-sg-id' 
    }));
    const quarantineSgId = getParam.Parameter?.Value;

    if (!quarantineSgId) {
        throw new Error("Quarantine SG ID missing in Parameter Store");
    }

    await ec2Client.send(new ModifyInstanceAttributeCommand({
        InstanceId: instanceId,
        Groups: [quarantineSgId]
    }));

    console.log(`Network isolation success`);
}

/**
 * Terminate active SSM sessions
 */
async function terminateSSMSessions(instanceId: string, region: string): Promise<number> {
    const ssmClient = new SSMClient({ region });
    let count = 0;
    try {
        const sessions = await ssmClient.send(new DescribeSessionsCommand({ State: 'Active' }));
        const targetSessions = sessions.Sessions?.filter(s => s.Target === instanceId) || [];
        for (const session of targetSessions) {
            await ssmClient.send(new TerminateSessionCommand({ SessionId: session.SessionId! }));
            count++;
        }
    } catch (e) { console.error("Session cleanup error:", e); }
    return count;
}

/**
 * Revoke IAM permissions by attaching inline deny policy
 */
async function revokeIAMForInstance(instanceId: string, region: string) {
    const ec2Client = new EC2Client({ region });
    const iamClient = new IAMClient({ region });
    try {
        const instanceData = await ec2Client.send(new DescribeInstancesCommand({ InstanceIds: [instanceId] }));
        const profileArn = instanceData.Reservations?.[0]?.Instances?.[0]?.IamInstanceProfile?.Arn;
        if (profileArn) {
            const profileName = profileArn.split('/').pop();
            const profileData = await iamClient.send(new GetInstanceProfileCommand({ InstanceProfileName: profileName! }));
            const roleName = profileData.InstanceProfile?.Roles?.[0]?.RoleName;
            if (roleName) {
                const revokePolicy = {
                    Version: "2012-10-17",
                    Statement: [{
                        Effect: "Deny", 
                        Action: "*", 
                        Resource: "*",
                        Condition: { DateLessThan: { "aws:TokenIssueTime": new Date().toISOString() } }
                    }]
                };
                await iamClient.send(new PutRolePolicyCommand({
                    RoleName: roleName, 
                    PolicyName: 'ASL-Revoke-Sessions', 
                    PolicyDocument: JSON.stringify(revokePolicy)
                }));
            }
        }
    } catch (e) { console.error("IAM revoke error:", e); }
}