#!/usr/bin/env node
import * as cdk from 'aws-cdk-lib';
import { TokyoSecurityStack } from '../lib/stacks/tokyo-stack'; 
import { SingaporeSecurityStack } from '../lib/stacks/singapore-stack';
import { TokyoEC2Stack } from '../lib/stacks/tokyo-ec2'; 
import { SingaporeEC2Stack } from '../lib/stacks/singapore-ec2';  

const app = new cdk.App();

// Singapore region stack (Aggregator)
new SingaporeSecurityStack(app, 'SingaporeSecurityStack', {
    env: { region: 'ap-southeast-1' }
});

// Tokyo region stack
new TokyoSecurityStack(app, 'TokyoSecurityStack', {
    env: { region: 'ap-northeast-1' }
});

// Singapore region demo stack
new SingaporeEC2Stack(app, 'SingaporeEC2Stack', {
    env: { region: 'ap-southeast-1' },
    regionName: 'Singapore',
});

// Tokyo region demo stack
new TokyoEC2Stack(app, 'TokyoEC2Stack', {
    env: { region: 'ap-northeast-1' },
    regionName: 'Tokyo',
});