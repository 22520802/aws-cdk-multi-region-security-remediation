import { PublishCommand, SNSClient } from '@aws-sdk/client-sns';
import { SecurityHubClient, BatchUpdateFindingsV2Command } from '@aws-sdk/client-securityhub';
import { 
    EC2Client, ModifyInstanceAttributeCommand, DescribeInstancesCommand, 
    DescribeIamInstanceProfileAssociationsCommand, DisassociateIamInstanceProfileCommand 
} from '@aws-sdk/client-ec2';
import { IAMClient, PutRolePolicyCommand, GetInstanceProfileCommand } from '@aws-sdk/client-iam';
import { 
    SSMClient, GetParameterCommand, PutParameterCommand, TerminateSessionCommand, 
    DescribeSessionsCommand, SendCommandCommand, GetCommandInvocationCommand 
} from '@aws-sdk/client-ssm';
import * as crypto from 'crypto';

const SNS_TOPIC_ARN = process.env.SNS_TOPIC_ARN;
const APPROVAL_URL_BASE = process.env.APPROVAL_URL_BASE;
const SIGNING_SECRET = process.env.SIGNING_SECRET || 'secret-key-change-me';

const snsClient = new SNSClient({});
const securityHubClient = new SecurityHubClient({});

/** Orchestrates forensics, network isolation, and sends approval notification */
export const handler = async (event: any): Promise<void> => {
    try {
        const findings = event.detail.findings;
        if (!findings || findings.length === 0) return;

        const resourceMap = new Map<string, any[]>();
        const allFindingIdentifiers: any[] = [];

        // Map findings to specific EC2 instances
        for (const finding of findings) {
            allFindingIdentifiers.push({
                CloudAccountUid: finding.cloud?.account?.uid,
                FindingInfoUid: finding.finding_info?.uid,
                MetadataProductUid: finding.metadata?.product?.uid,
            });

            const instanceId = finding.resources?.find((r: any) => r.type === 'AWS::EC2::Instance')?.uid;
            if (instanceId) {
                if (!resourceMap.has(instanceId)) resourceMap.set(instanceId, []);
                resourceMap.get(instanceId)?.push(finding);
            }
        }

        for (const [instanceId, instanceFindings] of resourceMap) {
            const firstFinding = instanceFindings[0];
            const region = firstFinding.cloud?.region || "ap-southeast-1";
            const ssmClient = new SSMClient({ region });
            const ec2Client = new EC2Client({ region });
            const lockKey = `/security/lock/${instanceId}`;

            // Check and set distributed lock via SSM
            try {
                await ssmClient.send(new GetParameterCommand({ Name: lockKey }));
                console.log(`Instance ${instanceId} is LOCKED. Skipping duplicate.`);
                continue; 
            } catch (err: any) {
                if (err.name !== 'ParameterNotFound') throw err;
            }

            await ssmClient.send(new PutParameterCommand({
                Name: lockKey, Value: 'PENDING_APPROVAL', Type: 'String', Overwrite: true
            }));

            // Collect instance and environment metadata
            const desc = await ec2Client.send(new DescribeInstancesCommand({ InstanceIds: [instanceId] }));
            const instanceData = desc.Reservations?.[0]?.Instances?.[0];
            const instanceName = instanceData?.Tags?.find((tag: any) => tag.Key === 'Name')?.Value || 'Unknown-Instance';

            const getParam = await ssmClient.send(new GetParameterCommand({ Name: '/security/forensics-bucket-name' }));
            const bucketName = getParam.Parameter?.Value;

            if (bucketName) {
                console.log(`Remediation start: ${instanceId} (${instanceName})`);

                await runForensicsWorkflow(instanceId, region, bucketName, instanceName);
                await quarantineNetwork(instanceId, region);
                await terminateSSMSessions(instanceId, region);
                await revokeIAMForInstance(instanceId, region);
                await detachIAMRole(instanceId, region);
                
                const approvalLink = generateApprovalLink(instanceId, region);
                const timeICT = new Date().toLocaleString('en-US', { timeZone: 'Asia/Ho_Chi_Minh', hour12: true });
                
                await snsClient.send(new PublishCommand({
                    TopicArn: SNS_TOPIC_ARN,
                    Subject: `[APPROVAL REQUIRED] Incident Containment - ${instanceName} (${instanceId})`,
                    Message: `
AWS SECURITY INCIDENT RESPONSE REPORT
==========================================
Status: ISOLATED & WAITING FOR DECISION
Time (ICT): ${timeICT}
Instance: ${instanceName} (${instanceId})
Region: ${region}

AUTOMATED ACTIONS TAKEN:
[v] Forensics memory dump captured
[v] Network isolated (Quarantine SG)
[v] IAM Role detached & Sessions revoked

PENDING ACTION:
The instance is currently running in isolation. 
To STOP this instance (finalize containment), please click the link below:

>>> CLICK TO STOP INSTANCE:
${approvalLink}

(Link valid for 24 hours)
==========================================
`
                }));
            }
        }

        // Update Security Hub finding status to Resolved
        if (allFindingIdentifiers.length > 0) {
            await securityHubClient.send(new BatchUpdateFindingsV2Command({
                FindingIdentifiers: allFindingIdentifiers,
                Comment: "Automated isolation completed. Pending human approval for shutdown.",
                StatusId: 2, 
            }));
        }
    } catch (error) {
        console.error('Fatal error:', error);
        throw error;
    }
};

/** Generates a signed URL for approval Lambda */
function generateApprovalLink(instanceId: string, region: string): string {
    if (!APPROVAL_URL_BASE) return "ERROR: Approval URL not configured";
    const expires = Date.now() + (24 * 60 * 60 * 1000);
    const signature = crypto.createHmac('sha256', SIGNING_SECRET)
                            .update(`${instanceId}:${region}:${expires}`)
                            .digest('hex');
    return `${APPROVAL_URL_BASE}?instanceId=${instanceId}&region=${region}&expires=${expires}&signature=${signature}`;
}

/** Executes AVML memory dump and uploads to S3 */
async function runForensicsWorkflow(instanceId: string, region: string, bucketName: string, instanceName: string) {
    const ssmClient = new SSMClient({ region });
    const s3Path = `s3://${bucketName}/forensics/${instanceName}/${instanceId}/$(date +%Y%m%d_%H%M%S)_mem.raw.xz`;

    const forensicsScript = [
        "set -e",
        "if [ ! -f /usr/local/bin/avml ]; then sudo curl -sL -o /usr/local/bin/avml https://github.com/microsoft/avml/releases/download/v0.14.0/avml && sudo chmod +x /usr/local/bin/avml; fi",
        "sudo mkdir -p /data-forensics && cd /data-forensics",
        "sudo /usr/local/bin/avml --source /proc/kcore --compress mem.raw.xz || sudo /usr/local/bin/avml --compress mem.raw.xz",
        `sudo aws s3 cp mem.raw.xz ${s3Path}`,
        "cd / && sudo rm -rf /data-forensics"
    ];

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
        if (status === 'Failed') throw new Error(`Forensics failed on instance ${instanceId}`);
    }
}

/** Attaches the Quarantine Security Group to instance */
async function quarantineNetwork(instanceId: string, region: string) {
    const ssmClient = new SSMClient({ region });
    const ec2Client = new EC2Client({ region });
    const getParam = await ssmClient.send(new GetParameterCommand({ Name: '/security/quarantine-sg-id' }));
    if (getParam.Parameter?.Value) {
        await ec2Client.send(new ModifyInstanceAttributeCommand({ 
            InstanceId: instanceId, 
            Groups: [getParam.Parameter.Value] 
        }));
    }
}

/** Terminates all active SSM sessions for instance */
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

/** Applies inline Deny policy to instance role */
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
                        Effect: "Deny", Action: "*", Resource: "*",
                        Condition: { DateLessThan: { "aws:TokenIssueTime": new Date().toISOString() } }
                    }]
                };
                await iamClient.send(new PutRolePolicyCommand({
                    RoleName: roleName, PolicyName: 'ASL-Revoke-Sessions', PolicyDocument: JSON.stringify(revokePolicy)
                }));
            }
        }
    } catch (e) { console.error("IAM revoke error:", e); }
}

/** Detaches IAM role profile from the instance */
async function detachIAMRole(instanceId: string, region: string) {
    const ec2Client = new EC2Client({ region });
    try {
        const associations = await ec2Client.send(new DescribeIamInstanceProfileAssociationsCommand({
            Filters: [{ Name: 'instance-id', Values: [instanceId] }]
        }));
        const associationId = associations.IamInstanceProfileAssociations?.[0]?.AssociationId;
        if (associationId) {
            await ec2Client.send(new DisassociateIamInstanceProfileCommand({ AssociationId: associationId }));
        }
    } catch (e) { console.error("Detach role error:", e); }
}