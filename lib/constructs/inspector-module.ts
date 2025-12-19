import { Construct } from 'constructs';
import * as cr from 'aws-cdk-lib/custom-resources'; 
import * as iam from 'aws-cdk-lib/aws-iam'; 

interface InspectorModuleProps {
    regionId: string;
}

export class InspectorModule extends Construct {
    constructor(scope: Construct, id: string, props: InspectorModuleProps) {
        super(scope, id);
        
        const regionTag = props.regionId.toUpperCase();
        
        //1. Inspector V2
        new cr.AwsCustomResource(
            this,
            `InspectorV2${regionTag}`,
            {
                onCreate: {
                    service: 'Inspector2',
                    action: 'enable',
                    parameters: {
                        resourceTypes: ['EC2', 'ECR', 'LAMBDA', 'LAMBDA_CODE'],
                    },
                    physicalResourceId: cr.PhysicalResourceId.of(`InspectorV2-${regionTag}`),
                },
                policy: cr.AwsCustomResourcePolicy.fromStatements([
                    new iam.PolicyStatement({
                        actions: [
                            'inspector2:Enable',
                            'iam:CreateServiceLinkedRole',
                        ],
                        resources: ['*'], 
                    }),
                ]),
            }
        );
    }
}