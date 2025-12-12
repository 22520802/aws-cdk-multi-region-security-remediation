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
        
        // --- 1. Kích hoạt Inspector V2 (Sử dụng Custom Resource) ---
        // Do không có tài nguyên CloudFormation trực tiếp để kích hoạt Inspector, 
        // ta dùng AwsCustomResource để gọi API 'Inspector2:Enable'.
        new cr.AwsCustomResource(
            this,
            `InspectorV2${regionTag}`,
            {
                // Hành động được gọi khi Custom Resource được tạo (Deployment)
                onCreate: {
                    service: 'Inspector2',
                    action: 'enable',
                    parameters: {
                        // Kích hoạt quét cho tất cả các loại tài nguyên chính
                        resourceTypes: ['EC2', 'ECR', 'LAMBDA', 'LAMBDA_CODE'],
                    },
                    // ID vật lý duy nhất cho tài nguyên
                    physicalResourceId: cr.PhysicalResourceId.of(`InspectorV2-${regionTag}`),
                },
                // Chính sách IAM cho Custom Resource để thực hiện API call
                policy: cr.AwsCustomResourcePolicy.fromStatements([
                    new iam.PolicyStatement({
                        actions: [
                            'inspector2:Enable',
                            // Quyền cần thiết để Inspector tự động tạo Service-Linked Role lần đầu
                            'iam:CreateServiceLinkedRole',
                        ],
                        resources: ['*'], // Cho phép trên mọi tài nguyên
                    }),
                ]),
                // Lưu ý: Tác giả Nhật Bản đã chỉ ra onDelete không hoạt động để vô hiệu hóa, 
                // nên ta bỏ qua onDelete để tránh lỗi.
            }
        );
    }
}