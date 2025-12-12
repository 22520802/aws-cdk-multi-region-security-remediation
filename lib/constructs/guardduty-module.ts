import { Construct } from 'constructs';
import * as guardduty from 'aws-cdk-lib/aws-guardduty';

interface GuardDutyModuleProps {
    regionId: string;
}

export class GuardDutyModule extends Construct {
    constructor(scope: Construct, id: string, props: GuardDutyModuleProps) {
        super(scope, id);

        const regionTag = props.regionId.toUpperCase();

        // 1. GuardDuty Detector
        new guardduty.CfnDetector(this, `Detector${regionTag}`, { 
            enable: true, 
            findingPublishingFrequency: 'FIFTEEN_MINUTES',
        });
    }
}