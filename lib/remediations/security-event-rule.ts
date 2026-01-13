import { Construct } from 'constructs';
import * as events from 'aws-cdk-lib/aws-events';
import * as targets from 'aws-cdk-lib/aws-events-targets';
import * as lambda from 'aws-cdk-lib/aws-lambda';

interface SecurityEventRuleProps {
    readonly targetLambda: lambda.IFunction;
    readonly regionTag: string;
}

/**
 * EventBridge rule to trigger remediation based on Security Hub findings
 */
export class SecurityEventRule extends Construct {
    constructor(scope: Construct, id: string, props: SecurityEventRuleProps) {
        super(scope, id);

        // Rule to capture High and Critical EC2 findings from Security Hub
        const securityHubRule = new events.Rule(this, `RemediationRule${props.regionTag}`, {
            description: `Trigger Lambda remediation for EC2 findings in ${props.regionTag}`,
            eventPattern: {
                source: ['aws.securityhub'],
                detailType: ['Findings Imported V2'],
                detail: {
                    findings: {
                        finding_info:{
                            "types": [
                            "Backdoor:EC2/C&CActivity.B",
                            "Backdoor:EC2/C&CActivity.B!DNS",
                            "Backdoor:Runtime/C&CActivity.B",
                            "Backdoor:Runtime/C&CActivity.B!DNS",
                            "Execution:Runtime/ReverseShell",
                            "Execution:Runtime/MaliciousFileExecuted",
                            "Execution:Runtime/SuspiciousTool",
                            "Backdoor:EC2/DenialOfService.Dns",
                            "Backdoor:EC2/DenialOfService.Tcp",
                            "Backdoor:EC2/DenialOfService.Udp",
                            "Backdoor:EC2/DenialOfService.UdpOnTcpPorts",
                            "Backdoor:EC2/DenialOfService.UnusualProtocol",
                            "Trojan:EC2/DNSDataExfiltration",
                            "PrivilegeEscalation:Runtime/RunContainerEscape",
                            "DefenseEvasion:Runtime/ProcessInjection.Proc",
                            "DefenseEvasion:Runtime/ProcessInjection.VirtualMemoryWrite",
                            "CryptoCurrency:EC2/BitcoinTool.B",
                            "CryptoCurrency:EC2/BitcoinTool.B!DNS",
                            "CryptoCurrency:Runtime/BitcoinTool.B",
                            "CryptoCurrency:Runtime/BitcoinTool.B!DNS",
                            "Impact:Runtime/CryptoMinerExecuted",
                            "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.InsideAWS",
                            "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS",
                            "AttackSequence:EC2/CompromisedInstanceGroup",
                            "Vulnerabilities"
                            ]
                        },
                        resources: { type: ["AWS::EC2::Instance"] },
                        severity: ['High', 'Critical'],
                        status: ['New']
                    }
                }
            },
        });

        // Set Lambda as the automated response target
        securityHubRule.addTarget(new targets.LambdaFunction(props.targetLambda));
    }
}