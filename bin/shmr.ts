#!/usr/bin/env node
import 'source-map-support/register';
import * as cdk from 'aws-cdk-lib';
import { TokyoSecurityStack } from '../lib/stacks/tokyo-stack'; 
import { SingaporeSecurityStack } from '../lib/stacks/singapore-stack';
import { TokyoEC2Stack } from '../lib/stacks/tokyo-ec2'; 
import { SingaporeEC2Stack } from '../lib/stacks/singapore-ec2';  

const app = new cdk.App();

// 1. Tokyo Security Stack
const tokyoSecurity = new TokyoSecurityStack(app, 'TokyoSecurityStack', {
    env: { region: 'ap-northeast-1' }
});

// 2. Singapore Security Stack
const singaporeSecurity = new SingaporeSecurityStack(app, 'SingaporeSecurityStack', {
    env: { region: 'ap-southeast-1' }
});
singaporeSecurity.addDependency(tokyoSecurity);

// 3. Tokyo EC2 Stack
const tokyoEC2 = new TokyoEC2Stack(app, 'TokyoEC2Stack', {
    env: { region: 'ap-northeast-1' },
    regionName: 'Tokyo',
});
tokyoEC2.addDependency(singaporeSecurity);

// 4. Singapore EC2 Stack
const singaporeEC2 = new SingaporeEC2Stack(app, 'SingaporeEC2Stack', {
    env: { region: 'ap-southeast-1' },
    regionName: 'Singapore',
});
singaporeEC2.addDependency(tokyoEC2);