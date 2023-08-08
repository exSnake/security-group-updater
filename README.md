# Cloudflare and Laravel Forge to AWS Security Group Updater
The Cloud Security Group Updater is a Python script designed to help automate the process of updating security group rules on aws. It utilizes the AWS Lambda service and leverages the boto3 library to interact with AWS resources. This script is particularly useful for maintaining the security of your cloud resources by allowing you to dynamically adjust the IP ranges that are allowed to access your instances.
## Features

**CloudFlare IP List Retrieval**: The script queries the CloudFlare API to obtain a list of IP ranges. These ranges are frequently used by CloudFlare services, which include a range of IP addresses from which traffic may originate.

**Forge IP List Retrieval**: Additionally, the script retrieves an IP list from Forge, a service related to Laravel. This list contains IP addresses that can be used to interact with Forge services.

**Security Group Rules Update**: The script then utilizes the retrieved IP lists to update security group rules. It dynamically adds and removes IP ranges to ensure that your cloud resources are only accessible from trusted sources.

**IPv4 and IPv6 Support**: The script is capable of updating both IPv4 and IPv6 security group rules, providing comprehensive security coverage for your resources.



## Usage
-----

1.  Environment Setup: Configure these environment variables:

-   `CLOUDFLARE_ADDITIONAL_IPS`: Comma-separated additional IPv4 CIDR blocks for CloudFlare IP ranges.

-   `FORGE_ADDITIONAL_IPS`: Comma-separated additional IPv4 CIDR blocks for Forge IP ranges.

-   `CLOUDFLARE_SECURITY_GROUP_IDS_LIST` or `CLOUDFLARE_SECURITY_GROUP_ID`: Comma-separated CloudFlare Security Group IDs or a single ID.

-   `FORGE_SECURITY_GROUP_IDS_LIST` or `FORGE_SECURITY_GROUP_ID`: Comma-separated Forge Security Group IDs or a single ID.

-   `CLOUDFLARE_PORTS_LIST` (optional): Comma-separated TCP ports for CloudFlare. Defaults to ports 80 and 443.

-   `FORGE_PORTS_LIST` (optional): Comma-separated TCP ports for Forge. Defaults to ports 22.

-   `UPDATE_IPV6` (optional): Set to `0` to disable updating IPv6 ranges; defaults to `1`.

2.  AWS Lambda Function Setup:

    -   Create an AWS Lambda function using the Python 3 runtime.
    -   Configure triggers (e.g., CloudWatch Events, API Gateway) to execute the function as needed.
3.  AWS IAM Policy Setup:

    -   Create an IAM policy with the following permissions:


    ```json
    {
        "Version": "2023-08-08",
        "Statement": [
            {
                "Sid": "VisualEditor0",
                "Effect": "Allow",
                "Action": [
                    "ec2:RevokeSecurityGroupIngress",
                    "s3:GetBucketPolicyStatus",
                    "ec2:AuthorizeSecurityGroupIngress",
                    "ec2:CreateTags",
                    "s3:PutBucketPolicy",
                    "s3:GetBucketPolicy",
                    "ec2:DescribeSecurityGroups"
                ],
                "Resource": "*"
            }
        ]
    }
    ```

    -   Assign this policy to an IAM role.
4.  Assign IAM Role to Lambda Function:

 - Associate the IAM role with the Lambda function. This grants the function the necessary permissions to interact with AWS resources.
5.  Automation: The script updates security group rules based on CloudFlare and Forge IP ranges, ensuring resource security.
## Important Note

Configure environment variables accurately, and ensure the Lambda function has the appropriate IAM role assigned. Incorrect setups could lead to unexpected behavior or security risks.
## Disclaimer

This script is provided as-is and is intended to serve as a starting point for automating security group rule updates. It's essential to review and test the script in your environment before deploying it to production. Additionally, be aware that AWS pricing may apply when using Lambda functions and other AWS services.


## Author

This script was developed by [@exSnake](https://www.github.com/exSnake) based on this script https://github.com/johnmccuk/cloudflare-ip-security-group-update.


