import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as securityhub from 'aws-cdk-lib/aws-securityhub';
import { ConfigRoleConstruct } from '../common/iam-role-construct';
import { ConfigModule } from '../constructs/config-module';
import { GuardDutyModule } from '../constructs/guardduty-module';
import { InspectorModule } from '../constructs/inspector-module';

/**
 * Secondary security stack for Tokyo collecting local findings.
 */
export class TokyoSecurityStack extends cdk.Stack {
    constructor(scope: Construct, id: string, props?: cdk.StackProps) {
        super(scope, id, props);

        const configRole = new ConfigRoleConstruct(this, 'SharedIAM').role;

        // 1. Local Security Hub (Spoke)
        new securityhub.CfnHubV2(this, 'SecurityHubTokyo', {
            tags: { Region: 'Tokyo' },
        });

        // 2. Regional Threat Detection & Compliance
        new GuardDutyModule(this, 'GuardDuty', { regionId: 'Tokyo' });
        
        new ConfigModule(this, 'ConfigService', { 
            configRole: configRole, 
            regionId: 'Tokyo' 
        });

        new InspectorModule(this, 'Inspector', { regionId: 'Tokyo' });
    }
}