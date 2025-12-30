import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as securityhub from 'aws-cdk-lib/aws-securityhub';
import { ConfigRoleConstruct } from '../common/iam-role-construct';
import { ConfigModule } from '../constructs/config-module';
import { GuardDutyModule } from '../constructs/guardduty-module';
import { InspectorModule } from '../constructs/inspector-module';

/**
 * Secondary Security Stack for Tokyo acting as a local finding collector
 */
export class TokyoSecurityStack extends cdk.Stack {
    constructor(scope: Construct, id: string, props?: cdk.StackProps) {
        super(scope, id, props);

        const configRole = new ConfigRoleConstruct(this, 'SharedIAM').role; 

        // Local Security Hub instance to collect regional findings
        new securityhub.CfnHubV2(this, 'SecurityHubTokyo', {
            tags: {
                Region: 'Tokyo',
            },
        });

        // Regional threat detection module
        new GuardDutyModule(this, 'GuardDuty', { regionId: 'Tokyo' });

        // Resource configuration tracking and regional forensic storage
        new ConfigModule(this, 'ConfigService', { 
            configRole: configRole, 
            regionId: 'Tokyo' 
        });

        // Vulnerability scanning module for local resources
        new InspectorModule(this, 'Inspector', { regionId: 'Tokyo' });
    }
}