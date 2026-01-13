import { APIGatewayProxyHandlerV2 } from 'aws-lambda';
import { EC2Client, StopInstancesCommand, DescribeInstancesCommand } from '@aws-sdk/client-ec2';
import { SSMClient, DeleteParameterCommand } from '@aws-sdk/client-ssm'; // Import SSM
import * as crypto from 'crypto';

const SIGNING_SECRET = process.env.SIGNING_SECRET || 'secret-key-change-me';

export const handler: APIGatewayProxyHandlerV2 = async (event) => {
    const params = event.queryStringParameters;
    
    // Validate parameters
    if (!params || !params.instanceId || !params.region || !params.signature || !params.expires) {
        return responseHTML('Error', 'Missing parameters', 'red');
    }

    const { instanceId, region, signature, expires } = params;

    // 1. Check expiration
    if (Date.now() > parseInt(expires)) {
        return responseHTML('Expired', 'This approval link has expired.', 'red');
    }

    // 2. Validate Signature (HMAC)
    const dataToSign = `${instanceId}:${region}:${expires}`;
    const expectedSignature = crypto.createHmac('sha256', SIGNING_SECRET).update(dataToSign).digest('hex');

    if (signature !== expectedSignature) {
        return responseHTML('Unauthorized', 'Invalid signature.', 'red');
    }

    // 3. Execute Stop Instance
    const ec2Client = new EC2Client({ region });
    const ssmClient = new SSMClient({ region }); // Initialize SSM Client

    try {
        // Fetch instance name for display
        const desc = await ec2Client.send(new DescribeInstancesCommand({ InstanceIds: [instanceId] }));
        const instanceName = desc.Reservations?.[0]?.Instances?.[0]?.Tags?.find(t => t.Key === 'Name')?.Value || instanceId;

        console.log(`Stopping instance ${instanceId}...`);
        await ec2Client.send(new StopInstancesCommand({ InstanceIds: [instanceId] }));

        // --- NEW LOGIC: DELETE LOCK AFTER SUCCESSFUL STOP ---
        const lockKey = `/security/lock/${instanceId}`;
        console.log(`Deleting lock for instance ${instanceId}...`);
        try {
            await ssmClient.send(new DeleteParameterCommand({ Name: lockKey }));
        } catch (e) {
            console.warn(`Failed to delete lock ${lockKey} (it might not exist or already deleted):`, e);
            // Non-blocking error, just log warning
        }
        // --- END NEW LOGIC ---

        return responseHTML('Action Confirmed', `Instance <b>${instanceName}</b> (${instanceId}) is being STOPPED.`, 'green');
    } catch (error: any) {
        console.error(error);
        return responseHTML('Failed', `AWS Error: ${error.message}`, 'red');
    }
};

function responseHTML(title: string, message: string, color: string) {
    return {
        statusCode: 200,
        headers: { 'Content-Type': 'text/html' },
        body: `
        <html>
            <body style="font-family: sans-serif; text-align: center; padding-top: 50px;">
                <h1 style="color: ${color};">${title}</h1>
                <p>${message}</p>
            </body>
        </html>`
    };
}