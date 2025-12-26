import { PublishCommand, SNSClient } from '@aws-sdk/client-sns';
import { SecurityHubClient, BatchUpdateFindingsV2Command } from '@aws-sdk/client-securityhub';
import { EC2Client, ModifyInstanceAttributeCommand, DescribeInstancesCommand } from '@aws-sdk/client-ec2';
import { IAMClient, PutRolePolicyCommand, GetInstanceProfileCommand } from '@aws-sdk/client-iam';
import { SSMClient, GetParameterCommand, TerminateSessionCommand, DescribeSessionsCommand } from '@aws-sdk/client-ssm';

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
            // Lấy Region chuẩn từ OCSF cloud object
            const region = finding.cloud?.region || "ap-southeast-1";

            // DUYỆT TẤT CẢ TÀI NGUYÊN TRONG DANH SÁCH (Vì đây là chuỗi tấn công nhiều máy)
            if (finding.resources && Array.isArray(finding.resources)) {
                for (const resource of finding.resources) {
                    const resourceId = resource.uid;
                    const resourceType = resource.type;

                    if (resourceType === 'AWS::EC2::Instance' && resourceId) {
                        console.log(`[ACTION] Processing remediation for: ${resourceId} in ${region}`);
                        
                        // 1. Cách ly Network
                        await quarantineInstance(resourceId, region);
                        
                        // 2. Thu hồi SSM Sessions
                        const ssmCount = await terminateSSMSessions(resourceId, region);
                        
                        // 3. Khóa IAM Role (Tự tìm Role Name từ InstanceID)
                        await revokeIAMForInstance(resourceId, region);

                        remediationLog += `- Remediation applied to: ${resourceId} (Sessions terminated: ${ssmCount})\n`;
                    }
                }
            }

            // Mapping định danh để update Security Hub
            ocsfIdentifiers.push({
                CloudAccountUid: finding.cloud?.account?.uid,
                FindingInfoUid: finding.finding_info?.uid,
                MetadataProductUid: finding.metadata?.product?.uid,
            });
        }

        if (remediationLog) {
            await snsClient.send(new PublishCommand({
                TopicArn: SNS_TOPIC_ARN,
                Subject: `[IMMEDIATE ACTION] Sequence Remediation Completed`,
                Message: `Detected an Attack Sequence. Actions taken:\n${remediationLog}`,
            }));

            await securityHubClient.send(new BatchUpdateFindingsV2Command({
                FindingIdentifiers: ocsfIdentifiers,
                Comment: "Automated quarantine and session revocation for all instances in sequence.",
                StatusId: 2, // RESOLVED
            }));
        }

    } catch (error) {
        console.error('Remediation Error:', error);
        throw error;
    }
};

// --- CÁC HÀM HỖ TRỢ (GIỮ NGUYÊN LOGIC AN TOÀN NHẤT) ---

async function quarantineInstance(instanceId: string, region: string) {
    const ssmClient = new SSMClient({ region });
    const ec2Client = new EC2Client({ region });

    const getParam = await ssmClient.send(new GetParameterCommand({ Name: '/security/quarantine-sg-id' }));
    const quarantineSgId = getParam.Parameter?.Value;
    if (!quarantineSgId) throw new Error(`Quarantine SG ID not found in ${region}`);

    await ec2Client.send(new ModifyInstanceAttributeCommand({
        InstanceId: instanceId,
        Groups: [quarantineSgId] 
    }));
}

async function terminateSSMSessions(instanceId: string, region: string): Promise<number> {
    const ssmClient = new SSMClient({ region });
    let count = 0;
    try {
        const sessions = await ssmClient.send(new DescribeSessionsCommand({ State: 'Active' }));
        const targetSessions = sessions.Sessions?.filter(s => s.Target === instanceId) || [];
        for (const session of targetSessions) {
            await ssmClient.send(new TerminateSessionCommand({ SessionId: session.SessionId }));
            count++;
        }
    } catch (e) { console.error("SSM Error:", e); }
    return count;
}

async function revokeIAMForInstance(instanceId: string, region: string) {
    const ec2Client = new EC2Client({ region });
    const iamClient = new IAMClient({ region });
    try {
        const instanceData = await ec2Client.send(new DescribeInstancesCommand({ InstanceIds: [instanceId] }));
        const iamArn = instanceData.Reservations?.[0]?.Instances?.[0]?.IamInstanceProfile?.Arn;
        
        if (iamArn) {
            const profileName = iamArn.split('/').pop();
            const profileData = await iamClient.send(new GetInstanceProfileCommand({ InstanceProfileName: profileName }));
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
                    PolicyName: 'ASL-Revoke-Old-Sessions',
                    PolicyDocument: JSON.stringify(revokePolicy)
                }));
            }
        }
    } catch (e) { console.error("IAM Revoke Error:", e); }
}