# Centralised Observability Automation #
Serverless application for the managed service automated observability tooling. It is built using the [AWS Serverless Application Model tool](https://aws.amazon.com/serverless/sam/).

The purpose of this repository is to deploy the serverless infrastructure and resources that govern the observability automation pipeline. The Github Actions Workflow pipeline will only trigger when annew release is created. Ensure that you use proper versioning tags when creating releases.

> [!IMPORTANT]
> Ensure that the setup.yaml is deployed into the account where the application is being hosted. You will also need to cross check the account IDs in the workflow files and samconfig.toml. The setup CloudFormation template deploys resouerces necessary (S3 Bucket, Github Actions Role, [GitHub OIDC trust relationship](https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/configuring-openid-connect-in-amazon-web-services)) for the pipeline to run. It creates a federated identity  which allows your GitHub Actions workflows to access resources in Amazon Web Services (AWS), without needing to store the AWS credentials as long-lived GitHub secrets.

## Deployment Environments
- Prod
    - Creating a release will deploy the production environment. Ensure that all tests have been performed prior to doing this.
- Dev
    - Creating a pre-release will deploy the development envrionment. Use this when testing new features.

## Components

### State Machine
The state machine governs the program flow of the application. 
![Diagram of the StateMachine](https://github.com/Fred-Luckham/centralised-observability-automation/blob/main/images/statemachine.png)

### Lambdas 
Multiple Lambdas serving functions of the application. These handle the event data and alert creation/deletion.

### SNS
An SNS topic and subscription that routes notifications to the service desk. This is used for the account health notifications as well as any application errors. 

#### Services Monitored
The current list of services covered by the observability automation is as follows:
- EC2
- ECS
- ELB
- SES
- VPN
- Lambda
- RDS

## Alert Parameters
The below thresholds are the default configurations for the deployed alerts. These configurations are set within the paramters block of the app template. Some of these can be overidden per resource using the customisation tags which are described below.

| Metric                 | Level  | Threshold | Services     |
|------------------------|--------|-----------|--------------| 
| CPU                    | P1     | 95%       | EC2, RDS, ECS|
| CPU                    | P2     | 90%       | EC2, RDS, ECS|
| CPU                    | P3     | 80%       | EC2, RDS, ECS|
| Memory                 | P1     | 95%       | EC2, RDS, ECS|
| Memory                 | P2     | 90%       | EC2, RDS, ECS|
| Memory                 | P3     | 80%       | EC2, RDS, ECS|
| Disk                   | P1     | 95%       | EC2, RDS, ECS|
| Disk                   | P2     | 90%       | EC2, RDS, ECS|
| Disk                   | P3     | 80%       | EC2, RDS, ECS|
| DiskQueueDepth         | P1     | 5         | RDS          |
| DiskQueueDepth         | P2     | 4         | RDS          |
| DiskQueueDepth         | P3     | 2         | RDS          |
| TargetResponseTime     | P1     | 3         | ELB          |
| TargetResponseTime     | P2     | 2         | ELB          |
| TargetResponseTime     | P3     | 1         | ELB          |
| UnHealthyHostCount     | P1     | 3         | ELB          |
| UnHealthyHostCount     | P2     | 2         | ELB          |
| UnHealthyHostCount     | P3     | 1         | ELB          |
| ReputationBounceRate   | P1     | 0.02%     | SES          |
| ReputationComplaintRate| P1     | 0.004%    | SES          |
| TunnelState            | P1     | 1         | VPN          |
| Status                 | P1     | 1         | EC2


| Setting           | Level  |
|-------------------|--------|
| Evaluation Periods| 15     |
| Period            | 60     |

## Customisation Tags
The default alert thresholds can be overridden using tags. These are applied the the resource being mononitored and they will automatically update the existing alert threshold for the relevant metric. The accepted customisatipon tags are shown below. Not all metrics can be customised, this is by design. To use these tags, add them to the chosen resource as a tag key, and then add the desired threshold as the key.

- P1-Error
- P1-Throttle
- P1-CPU
- P2-CPU
- P3-CPU
- P1-Memory
- P2-Memory
- P3-Memory
- P1-Disk
- P2-Disk
- P3-Disk
- P1-DiskQueueDepth
- P2-DiskQueueDepth
- P3-DiskQueueDepth
