import { Construct } from 'constructs';
import * as guardduty from 'aws-cdk-lib/aws-guardduty';

interface GuardDutyModuleProps {
    regionId: string;
}

/**
 * Setup GuardDuty threat detection
 */
export class GuardDutyModule extends Construct {
    constructor(scope: Construct, id: string, props: GuardDutyModuleProps) {
        super(scope, id);

        const regionTag = props.regionId.toUpperCase();

        // Enable GuardDuty detector with high frequency publishing
        new guardduty.CfnDetector(this, `Detector${regionTag}`, { 
            enable: true, 
            findingPublishingFrequency: 'FIFTEEN_MINUTES',
            features: [
                {
                    name: 'RUNTIME_MONITORING',
                    status: 'ENABLED',
                    additionalConfiguration: [
                        {
                            name: "EC2_AGENT_MANAGEMENT",
                            status: "ENABLED",
                        }
                    ]
                }
            ]
        });
    }
}