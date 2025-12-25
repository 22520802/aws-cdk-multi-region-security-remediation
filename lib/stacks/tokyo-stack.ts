    import * as cdk from 'aws-cdk-lib';
    import { Construct } from 'constructs';
    import * as securityhub from 'aws-cdk-lib/aws-securityhub';
    import { ConfigRoleConstruct } from '../common/iam-role-construct';
    import { ConfigModule } from '../constructs/config-module';
    import { GuardDutyModule } from '../constructs/guardduty-module';
    import { InspectorModule } from '../constructs/inspector-module';

    export class TokyoSecurityStack extends cdk.Stack {
        constructor(scope: Construct, id: string, props?: cdk.StackProps) {
            super(scope, id, props);

            const configRole = new ConfigRoleConstruct(this, 'SharedIAM').role; 

            // 1. Security Hub
            new securityhub.CfnHubV2(this, 'SecurityHubTokyo', {
                tags: {
                    Region: 'Tokyo',
                },
            });

            // 2. GuardDuty
            new GuardDutyModule(this, 'GuardDuty', { regionId: 'Tokyo' });

            // 3. Config
            new ConfigModule(this, 'ConfigService', { 
                configRole: configRole, 
                regionId: 'Tokyo' 
            });

            // 4. Inspector
            new InspectorModule(this, 'Inspector', { regionId: 'Tokyo' });
        }
    }