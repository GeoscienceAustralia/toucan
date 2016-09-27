import boto3
import argparse
import json
import time
import requests
import zipfile
import re

def create_elasticsearch_domain(name, account_id, boto_session, lambda_role, cidr):
    """
    Create Elastic Search Domain

    """

    boto_elasticsearch = boto_session.client('es')
    total_time = 0

    access_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {
                    "AWS": lambda_role
                },
                "Action": "es:*",
                "Resource": "arn:aws:es:ap-southeast-2:{0}:domain/{1}/*".format(account_id, name)
            },
            {
                "Effect": "Allow",
                "Principal": {
                    "AWS": "*"
                },
                "Action": "es:*",
                "Resource": "arn:aws:es:ap-southeast-2:{0}:domain/{1}/*".format(account_id, name),
                "Condition": {
                    "IpAddress": {
                        "aws:SourceIp": "{0}".format(cidr)
                    }
                }
            }
        ]
    }

    endpoint = None

    while True:
        try:
            boto_elasticsearch.create_elasticsearch_domain(
                DomainName=name,
                ElasticsearchVersion='2.3',
                ElasticsearchClusterConfig={
                    'InstanceType': 't2.micro.elasticsearch',
                    'InstanceCount': 1,
                    'DedicatedMasterEnabled': False,
                    'ZoneAwarenessEnabled': False
                },
                EBSOptions={
                    'EBSEnabled': True,
                    'VolumeType': 'gp2',
                    'VolumeSize': 20
                },
                AccessPolicies=json.dumps(access_policy)
            )

            es_status = boto_elasticsearch.describe_elasticsearch_domain(DomainName=name)
            processing = es_status['DomainStatus']['Processing']

            if not processing:
                endpoint = es_status['DomainStatus']['Endpoint']
                print('Domain: {0} has been created!'.format(name))
                break
            else:
                print('Domain: {0} is still processing. Waiting for 120 seconds before checking again'.format(name))

        except Exception:
            print('Domain: {0} is still processing. Waiting for 120 seconds before checking again'.format(name))
            total_time += 120
            if total_time > 1800:
                print('Script has been running for over 30 minutes... This likely means that your elastic search domain'
                      ' has not created successfully. Please check the Elasticsearch Service dashboard in AWS console'
                      ' and delete the domain named {0} if it exists before trying again'.format(name))
                exit(1)
            time.sleep(120)


    return endpoint


def configure_kibana(endpoint, lambda_arn, boto_session):
    """
    Configures kibana
    and Invokes the lambda function for the first time
    """

    cw_template_json = {
        "template": "cw-*",
        "mappings": {
            "_default_": {
                "properties": {
                    "instance": {
                        "index": "not_analyzed",
                        "type": "string"
                        },
                    "instanceName": {
                        "index": "not_analyzed",
                        "type": "string"
                        },
                    "account": {
                        "index": "not_analyzed",
                        "type": "string"
                        }
                    }
                }
            }
        }

    index_pattern_json = {
        "title": "cw-*",
        "timeFieldName": "timestamp"
    }

    default_index_json = {
        "defaultIndex": "cw-*"
    }

    print('Deleting any non-formated events that have arrived')
    requests.delete('https://{0}/cw*'.format(endpoint))

    print('Creating a data template to format the data from cloudwatch events')
    requests.put('https://{0}/_template/cw-*'.format(endpoint), data=json.dumps(cw_template_json))

    print('Creating an index-pattern called cw-* to capture incoming cloudwatch metrics')
    requests.put('https://{0}/.kibana-4/index-pattern/cw-*'.format(endpoint), data=json.dumps(index_pattern_json))

    print('Executing Lambda Function for the first time and waiting 60 seconds for execution to complete')
    boto_lambda = boto_session.client('lambda')
    boto_lambda.invoke(FunctionName=lambda_arn)
    time.sleep(60)

    # The below doesn't appear to work for some reason.
    print('Designating cw-* as the default index pattern')
    requests.put('https://{0}/.kibana-4/config/4.1.2'.format(endpoint), data=json.dumps(default_index_json))

    print('Kibana has been configured!')

def create_cloudwatch_rule(name, lambda_arn, endpoint, region, boto_session):
    """
    Creates a cloudwatch event rule to push data to an elasticsearch domain endpoint

    """

    boto_cloudwatch = boto_session.client('events')
    event_rule = {
        "metrics": [
            "CPUUtilization",
            "DiskSpaceUtilization",
            "MemoryUtilization",
            "StatusCheckFailed",
            "NetworkIn",
            "NetworkOut",
            "DiskReadBytes",
            "DiskWriteBytes"
            ],
        "aggtime": 5,
        "endpoint": endpoint,
        "measurement": "Average",
        "region": region
    }

    print('Creating a Cloudwatch rule \'cloudwatch_to_{0}_es\''.format(name))
    rule = boto_cloudwatch.put_rule(
        Name='cloudwatch_to_{0}_es'.format(name),
        ScheduleExpression='rate(5 minutes)',
        State='ENABLED',
        Description='Push cloudwatch metrics to {0} elasticsearch'.format(name)
    )

    print('Creating a target for the Cloudwatch rule, pointing it at the lambda function')
    target = boto_cloudwatch.put_targets(
        Rule='cloudwatch_to_{0}_es'.format(name),
        Targets=[
            {
                'Id': '0',
                'Arn': lambda_arn,
                'Input': json.dumps(event_rule),
            }
        ]
    )


def create_lambda_function(name, boto_session, role_arn):
    """
    Creates a lambda function that will handle

    """

    # Wait for the IAM Role to be ready to attach
    time.sleep(60)

    zip = zipfile.ZipFile('{0}_processing_lambda.zip'.format(name), 'w')
    zip.write('./cloudwatch_metrics.js')
    zip.close()

    boto_lambda = boto_session.client('lambda')

    print('Creating a lambda function: \'{0}_lambda_function\' using the local file \'cloudwatch_metrics.js\''.format(name))
    with open('{0}_processing_lambda.zip'.format(name), 'rb') as zfile:
        response = boto_lambda.create_function(
            FunctionName='{0}_lambda_function'.format(name),
            Runtime='nodejs4.3',
            Role=role_arn,
            Handler='cloudwatch_metrics.handler',
            Code={
                'ZipFile': zfile.read()
            },
            Description='A Lambda function to process cloudwatch metrics and send to elasticsearch domain {0}'.format(name),
            Timeout=15
        )

    return response['FunctionArn']


def create_lambda_iam_role(name, boto_session):
    """
    Creates IAM Policy and Role to attach to the lambda function to handle cloudwatch metrics

    """

    boto_iam = boto_session.client('iam')

    policy_document = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "cloudwatch:GetMetricStatistics"
                ],
                "Resource": [
                    "*"
                ]
            },
            {
                "Effect": "Allow",
                "Action": [
                    "ec2:DescribeInstances"
                ],
                "Resource": [
                    "*"
                ]
            },
            {
                "Effect": "Allow",
                "Action": [
                    "logs:CreateLogGroup",
                    "logs:CreateLogStream",
                    "logs:PutLogEvents"
                ],
                "Resource": "arn:aws:logs:*:*:*"
            }
        ]
    }

    assumerole_document = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {
                    "Service": "lambda.amazonaws.com"
                },
                "Action": "sts:AssumeRole"
            }
        ]
    }

    print('Creating IAM Policy \'{0}_processing_lambda_policy\' to enable access to cloudwatch metrics'.format(name))
    policy = boto_iam.create_policy(
        PolicyName='{0}_processing_lambda_policy'.format(name),
        PolicyDocument=json.dumps(policy_document),
        Description='Iam Policy created for elasticsearch domain \'{0}\' that should give access to process cloudwatch'
                    ' metrics to a lambda function'.format(name)
    )

    print('Creating IAM Role \'{0}_processing_lambda_role\' to apply to lambda function'.format(name))
    role = boto_iam.create_role(
        RoleName='{0}_processing_lambda_role'.format(name),
        AssumeRolePolicyDocument=json.dumps(assumerole_document)
    )

    print('Attaching IAM Policy to IAM Role to enable cloudwatch metrics access via the role')
    boto_iam.attach_role_policy(
        RoleName=role['Role']['RoleName'],
        PolicyArn=policy['Policy']['Arn']
    )

    return role['Role']['Arn']


def update_lambda_permissions(lambda_arn, boto_session):
    """
    Updates Lambda to add permissions for cloudwatch to trigger it.

    """

    boto_lambda = boto_session.client('lambda')

    print('Updating lambda permissions to allow events.amazonaws.com to invoke the function')
    boto_lambda.add_permission(
        FunctionName=lambda_arn,
        StatementId='0',
        Action='lambda:InvokeFunction',
        Principal='events.amazonaws.com'
    )


def delete_elk(name, boto_session):
    """
    Deletes an elk environment with the specified name

    """

    # Delete Cloudwatch objects
    cw_rule_name = 'cloudwatch_to_{0}_es'.format(name)
    print('Deleting Cloudwatch rule: {0}'.format(cw_rule_name))
    try:
        boto_cloudwatch = boto_session.client('events')

        boto_cloudwatch.remove_targets(Rule=cw_rule_name,
                                       Ids=['0'])
        boto_cloudwatch.delete_rule(Name=cw_rule_name)
    except Exception as e:
        if 'ResourceNotFoundException' not in str(e):
            print(e)
        else:
            print('Cloudwatch rule {0} did not exist, going ahead with other deletions'.format(cw_rule_name))

    # Delete Lambda object
    lambda_name = '{0}_lambda_function'.format(name)
    print('Deleting Lambda function: {0}'.format(lambda_name))
    try:
        boto_lambda = boto_session.client('lambda')

        boto_lambda.delete_function(FunctionName=lambda_name)
    except Exception as e:
        if 'ResourceNotFoundException' not in str(e):
            print(e)
        else:
            print('Lambda function {0} did not exist, going ahead with other deletions'.format(lambda_name))

    # Delete IAM objects
    role_name = '{0}_processing_lambda_role'.format(name)
    policy_name = '{0}_processing_lambda_policy'.format(name)

    policy_arn = 'NO POLICY FOUND IN SEARCH'

    try:
        boto_iam = boto_session.client('iam')

        for policy in boto_iam.list_policies()['Policies']:
            if policy['PolicyName'] == policy_name:
                policy_arn = policy['Arn']
    except Exception as e:
        print(e)


    print('Deleting iam objects: {0} and {1}'.format(role_name, policy_name))

    try:
        boto_iam = boto_session.client('iam')

        boto_iam.detach_role_policy(RoleName=role_name,
                                    PolicyArn=policy_arn)
        boto_iam.delete_role(RoleName=role_name)
        boto_iam.delete_policy(PolicyArn=policy_arn)
    except Exception as e:
        if 'ResourceNotFoundException' not in str(e) and 'NoSuchEntity' not in str(e):
            print(e)
        else:
            print('IAM Role {0} or IAM Policy {1} did not exist, going ahead with other deletions'.format(role_name, policy_name))

    # Delete elasticsearch domain object
    print('Deleting Elasticsearch domain: {0}'.format(name))
    try:
        boto_elasticsearch = boto_session.client('es')

        boto_elasticsearch.delete_elasticsearch_domain(DomainName=name)
    except Exception as e:
        if 'ResourceNotFoundException' not in str(e):
            print(e)
        else:
            print('Elasticsearch domain {0} did not exist'.format(name))

    print('All Eck objects for: \'{0}\' have been deleted'.format(name))


def main():
    """
    Create Elastic Search Domain

    """

    parser = argparse.ArgumentParser()
    parser.add_argument('-p', '--profile',
                        default='default',
                        help='Which profile to use (from your aws credentials file. default: default')
    parser.add_argument('-n', '--name',
                        default='elk',
                        help='What name to give the elk instance. default: elk')
    parser.add_argument('-a', '--action',
                        default='create',
                        help='The action to perform. options: create OR delete. delete will delete all elk objects with'
                             ' the provided name (-n) default: create')
    parser.add_argument('-c', '--cidr',
                        required=True,
                        help='A cidr block to limit access to this elk to')

    args = parser.parse_args()

    profile = args.profile
    cidr = args.cidr
    domainname = args.name
    action = args.action.upper()
    regex_pattern = '^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(\/([0-9]|[1-2][0-9]|3[0-2]))$'
    if not re.match(regex_pattern, cidr):
        print('The provided CIDR: \'{0}\' does not match a cidr pattern. eg. 1-255.0-255.0-255.0-255/0-32'.format(cidr))
        exit(1)

    session = boto3.Session(profile_name=profile)

    sts = session.client('sts')
    account_id = sts.get_caller_identity()['Account']

    if action in ['CREATE']:
        role_arn = create_lambda_iam_role(domainname, session)
        endpoint = create_elasticsearch_domain(domainname, account_id, session, role_arn, cidr)
        region = endpoint.split('.')[1]
        lambda_arn = create_lambda_function(domainname, session, role_arn)
        create_cloudwatch_rule(domainname, lambda_arn, endpoint, region, session)
        update_lambda_permissions(lambda_arn, session)
        configure_kibana(endpoint, lambda_arn, session)
        print("Kibana Endpoint: 'https://{0}/_plugin/kibana/'".format(endpoint))
    elif action in ['DELETE']:
        delete_elk(domainname, session)
    else:
        print('Unrecognised action specified, please set either CREATE or DELETE')


if __name__ == '__main__':
    main()
