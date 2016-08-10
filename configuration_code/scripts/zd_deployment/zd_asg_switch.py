import argparse
import sys

import boto3

# AWS autoscaling group type name
ASG_TYPE = 'AWS::AutoScaling::AutoScalingGroup'
# AWS elastic load balancer type name
ELB_TYPE = 'AWS::ElasticLoadBalancing::LoadBalancer'
# List of stable/good cloudformation resource states
GOOD_STATES = ['CREATE_COMPLETE', 'UPDATE_COMPLETE']


class StackSwitchError(Exception):
    """
    If there is an error or inconsistent state encountered during stack switch
    """

    def __init__(self, value):
        self.value = value


def stack_switch(cf_stack_name, logical_stack_name, unit_name):
    """
    Switch an Amazonia zd autoscaling unit in a given Amazonia stack
    :param cf_stack_name: Cloudformation stack name
    :param logical_stack_name: Amazonia stack name
    :param unit_name: Amazonia unit name
    """
    cloudformation_client = boto3.client('cloudformation')

    response = cloudformation_client.list_stack_resources(
        StackName=cf_stack_name
    )
    resources = response['StackResourceSummaries']
    next_token = None
    if 'NextToken' in response:
        next_token = response['NextToken']

    # just in case the stack gets particularly large
    while next_token is not None:
        response = cloudformation_client.list_stack_resources(
            StackName=cf_stack_name,
            NextToken=next_token
        )
        resources.extend(response['StackResourceSummaries'])
        if 'NextToken' in response:
            next_token = response['NextToken']
        else:
            next_token = None

    data = {
        'logical_stack_name': logical_stack_name,
        'unit_name': unit_name
    }

    blue_asg_id = None
    green_asg_id = None
    active_elb_id = None
    inactive_elb_id = None
    blue_asg_name = '{asg_colour}{logical_stack_name}{unit_name}Asg'.format(asg_colour='blue', **data)
    green_asg_name = '{asg_colour}{logical_stack_name}{unit_name}Asg'.format(asg_colour='green', **data)
    active_elb_name = '{elb_state}{logical_stack_name}{unit_name}Elb'.format(elb_state='active', **data)
    inactive_elb_name = '{elb_state}{logical_stack_name}{unit_name}Elb'.format(elb_state='inactive', **data)

    for resource in resources:  # type: dict
        if resource['LogicalResourceId'] == blue_asg_name and resource['ResourceType'] == ASG_TYPE:
            if resource['ResourceStatus'] in GOOD_STATES:
                blue_asg_id = resource['PhysicalResourceId']
            else:
                raise StackSwitchError('Error: {0} had status {1}'.format(blue_asg_name, resource['ResourceStatus']))
        elif resource['LogicalResourceId'] == green_asg_name and resource['ResourceType'] == ASG_TYPE:
            if resource['ResourceStatus'] in GOOD_STATES:
                green_asg_id = resource['PhysicalResourceId']
            else:
                raise StackSwitchError('Error: {0} had status {1}'.format(green_asg_name, resource['ResourceStatus']))
        elif resource['LogicalResourceId'] == active_elb_name and resource['ResourceType'] == ELB_TYPE:
            if resource['ResourceStatus'] in GOOD_STATES:
                active_elb_id = resource['PhysicalResourceId']
            else:
                raise StackSwitchError('Error: {0} had status {1}'.format(active_elb_name, resource['ResourceStatus']))
        elif resource['LogicalResourceId'] == inactive_elb_name and resource['ResourceType'] == ELB_TYPE:
            if resource['ResourceStatus'] in GOOD_STATES:
                inactive_elb_id = resource['PhysicalResourceId']
            else:
                raise StackSwitchError(
                    'Error: {0} had status {1}'.format(inactive_elb_name, resource['ResourceStatus']))

    status = None

    asg_client = boto3.client('autoscaling')

    response = asg_client.describe_auto_scaling_groups(
        AutoScalingGroupNames=[blue_asg_id]
    )

    for autoscaling_group in response['AutoScalingGroups']:
        for loadbalancer_name in autoscaling_group['LoadBalancerNames']:
            if loadbalancer_name == active_elb_id:
                status = 'blue'
            elif loadbalancer_name == inactive_elb_id:
                status = 'green'
            else:
                raise StackSwitchError('Could not identify state of unit, blue asg loadbalancer id was {0}'
                                       .format(loadbalancer_name))
    print('Detected {0} in {1} state, switching...'.format(unit_name, status))
    if status == 'blue':
        print(asg_client.attach_load_balancers(AutoScalingGroupName=blue_asg_id, LoadBalancerNames=[inactive_elb_id]))
        print(asg_client.attach_load_balancers(AutoScalingGroupName=green_asg_id, LoadBalancerNames=[active_elb_id]))
        print(asg_client.detach_load_balancers(AutoScalingGroupName=blue_asg_id, LoadBalancerNames=[active_elb_id]))
        print(asg_client.detach_load_balancers(AutoScalingGroupName=green_asg_id, LoadBalancerNames=[inactive_elb_id]))
    elif status == 'green':
        print(asg_client.attach_load_balancers(AutoScalingGroupName=blue_asg_id, LoadBalancerNames=[active_elb_id]))
        print(asg_client.attach_load_balancers(AutoScalingGroupName=green_asg_id, LoadBalancerNames=[inactive_elb_id]))
        print(asg_client.detach_load_balancers(AutoScalingGroupName=blue_asg_id, LoadBalancerNames=[inactive_elb_id]))
        print(asg_client.detach_load_balancers(AutoScalingGroupName=green_asg_id, LoadBalancerNames=[active_elb_id]))


def get_args(argv):
    """
    Handles all the arguments that are passed into the script
    :param argv: command line arguments
    :return: Returns a parsed version of the arguments.
    """
    parser = argparse.ArgumentParser(
        description='Script to substitute switch AREMI autoscaling units')
    parser.add_argument("-C", "-c", "--cf_stack_name",
                        help="The name of the cloudformation stack",
                        dest="cf_stack_name",
                        required=True)
    parser.add_argument("-L", "-l", "--logical_stack_name",
                        help="The name of amazonia stack",
                        dest="logical_stack_name",
                        required=True)
    parser.add_argument("-U", "-u", "--unit_name",
                        help="The name of the unit to switch",
                        dest="unit_name",
                        required=True)
    return parser.parse_args(argv)


def main(argv):
    """
    This script is oddly specific to aremi and will be changed in the future,
    it takes the supplied arguments and substitutes the aremi release placeholder with a specific
    aremi release version name
    :param argv: command line arguments
    """
    args = get_args(argv)
    stack_switch(cf_stack_name=args.cf_stack_name, logical_stack_name=args.logical_stack_name, unit_name=args.unit_name)


if __name__ == "__main__":
    main(sys.argv[1:])
