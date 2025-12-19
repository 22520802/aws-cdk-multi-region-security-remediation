import { PublishCommand, SNSClient } from '@aws-sdk/client-sns';
import {
    SecurityHubClient,
    BatchUpdateFindingsV2Command,
} from '@aws-sdk/client-securityhub';
import { EC2Client, ModifyInstanceAttributeCommand } from '@aws-sdk/client-ec2';
import { SSMClient, GetParameterCommand } from '@aws-sdk/client-ssm';

const SNS_TOPIC_ARN = process.env.SNS_TOPIC_ARN;
const snsClient = new SNSClient({});
const securityHubClient = new SecurityHubClient({});

export const handler = async (event: any): Promise<void> => {
    try {
        const findings = event.detail.findings;
        if (!findings || findings.length === 0) return;

        const region = findings[0].cloud?.region || "ap-southeast-1";
        const ocsfIdentifiers: any[] = [];
        let remediationLog = "";

        for (const finding of findings) {
            const resourceId = finding.resources?.[0]?.uid;
            const resourceType = finding.resources?.[0]?.type;

            if (resourceType === 'AWS::EC2::Instance' && resourceId) {
                await quarantineInstance(resourceId, region);
                remediationLog += `- Isolated Instance: ${resourceId} in ${region}\n`;
            }

            ocsfIdentifiers.push({
                CloudAccountUid: finding.cloud?.account?.uid || finding.AwsAccountId,
                FindingInfoUid: finding.finding_info?.uid || finding.Id,
                MetadataProductUid: finding.metadata?.product?.uid || finding.ProductArn,
            });
        }

        // SNS
        await snsClient.send(new PublishCommand({
            TopicArn: SNS_TOPIC_ARN,
            Subject: `[ACTION TAKEN] Security Remediation in ${region}`,
            Message: `The following actions were taken automatically:\n${remediationLog}`,
        }));

        //  Update status
        await securityHubClient.send(new BatchUpdateFindingsV2Command({
            FindingIdentifiers: ocsfIdentifiers,
            Comment: "Automated quarantine applied via Lambda.",
            StatusId: 2,
        }));

    } catch (error) {
        console.error('Remediation Error:', error);
        throw error;
    }
};

async function quarantineInstance(instanceId: string, region: string) {
    // 1. SG ID SSM
    const ssmClient = new SSMClient({ region: region });
    const getParam = await ssmClient.send(new GetParameterCommand({
        Name: '/security/quarantine-sg-id'
    }));
    
    const quarantineSgId = getParam.Parameter?.Value;
    if (!quarantineSgId) throw new Error(`Could not find Quarantine SG ID in SSM for ${region}`);

    // 2. Security Group
    const ec2Client = new EC2Client({ region: region });
    await ec2Client.send(new ModifyInstanceAttributeCommand({
        InstanceId: instanceId,
        Groups: [quarantineSgId] 
    }));
    
    console.log(`Successfully quarantined ${instanceId} using ${quarantineSgId}`);
}