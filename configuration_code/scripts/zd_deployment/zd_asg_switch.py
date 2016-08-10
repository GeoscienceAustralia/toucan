import argparse
import sys

import boto3

# Valid cloud formation resource mappings
RESOURCE_TYPES = {'Asg': 'AWS::AutoScaling::AutoScalingGroup',
                  'Elb': 'AWS::ElasticLoadBalancing::LoadBalancer'}

# List of stable/good cloudformation resource states
GOOD_STATES = ['CREATE_COMPLETE', 'UPDATE_COMPLETE']


class StackSwitchError(Exception):
    """
    If there is an error or inconsistent state encountered during stack switch
    """

    def __init__(self, value):
        self.value = value


def lookup_resource_id(cf_stack_name, logical_stack_name, unit_name, object_type, object_name):
    """
    Return the AWS identifier for a cloud formation resource
    :param cf_stack_name: Cloudfromation stack name
    :param logical_stack_name: Amazonia stack name
    :param unit_name: Amazonia unit name
    :param object_type: 'Asg' or 'Elb'
    :param object_name: 'blue' or 'green' for ASGs, 'active' and 'inactive' for ELBs
    :return: AWS identifier of specified resource
    """
    cloudformation_client = boto3.client('cloudformation')

    logical_resource_name = object_name+logical_stack_name+unit_name+object_type

    response = cloudformation_client.describe_stack_resource(
        StackName=cf_stack_name,
        LogicalResourceId=logical_resource_name
    )

    resource = response['StackResourceDetail']

    if resource['ResourceType'] != RESOURCE_TYPES[object_type]:
        raise StackSwitchError('Error: {0} had type of {1}, was expecting {2}'.format(logical_resource_name,
                                                                                      resource['ResourceType'],
                                                                                      RESOURCE_TYPES[object_type]))
    if resource['ResourceStatus'] not in GOOD_STATES:
        raise StackSwitchError(
            'Error: {0} had status {1}'.format(logical_resource_name, resource['ResourceStatus']))

    return resource['PhysicalResourceId']


def check_response(http_response):
    """
    Check http response code for stack switch operation, raise error if not 200
    :param http_response: Boto3 http response
    """
    http_response = http_response['ResponseMetadata']['HTTPStatusCode']
    if http_response != 200:
        raise StackSwitchError('Error: received the following non-success HTTP status code: {0}'.format(http_response))


def check_state(asg_client, blue_asg_id, active_elb_id, inactive_elb_id):
    """
    Check which ELB is attached to the blue ASG, raise error if sate is unrecognized
    :param asg_client: Boto3 autoscaling client
    :param blue_asg_id: AWS resource ID for blue asg
    :param active_elb_id: AWS resource ID for active elb
    :param inactive_elb_id: AWS resource ID for inactive elb
    :return: state of zd unit
    """
    state = None

    response = asg_client.describe_auto_scaling_groups(
        AutoScalingGroupNames=[blue_asg_id]
    )

    for autoscaling_group in response['AutoScalingGroups']:
        for loadbalancer_name in autoscaling_group['LoadBalancerNames']:
            if loadbalancer_name == active_elb_id:
                state = 'blue'
            elif loadbalancer_name == inactive_elb_id:
                state = 'green'
            else:
                raise StackSwitchError('Could not identify state of unit, {0} loadbalancer id was {0}'
                                       .format(blue_asg_id, loadbalancer_name))
    return state


def stack_switch(cf_stack_name, logical_stack_name, unit_name):
    """
    Switch an Amazonia zd autoscaling unit in a given Amazonia stack
    :param cf_stack_name: Cloudformation stack name
    :param logical_stack_name: Amazonia stack name
    :param unit_name: Amazonia unit name
    """
    asg_client = boto3.client('autoscaling')

    blue_asg_id = lookup_resource_id(cf_stack_name, logical_stack_name, unit_name, 'Asg', 'blue')
    green_asg_id = lookup_resource_id(cf_stack_name, logical_stack_name, unit_name, 'Asg', 'green')
    active_elb_id = lookup_resource_id(cf_stack_name, logical_stack_name, unit_name, 'Elb', 'active')
    inactive_elb_id = lookup_resource_id(cf_stack_name, logical_stack_name, unit_name, 'Elb', 'inactive')

    state = check_state(asg_client, blue_asg_id, active_elb_id, inactive_elb_id)
    print('Detected {0} in {1} state, switching...'.format(unit_name, state))
    if state == 'blue':
        check_response(
            asg_client.attach_load_balancers(AutoScalingGroupName=blue_asg_id, LoadBalancerNames=[inactive_elb_id]))
        check_response(
            asg_client.attach_load_balancers(AutoScalingGroupName=green_asg_id, LoadBalancerNames=[active_elb_id]))
        check_response(
            asg_client.detach_load_balancers(AutoScalingGroupName=blue_asg_id, LoadBalancerNames=[active_elb_id]))
        check_response(
            asg_client.detach_load_balancers(AutoScalingGroupName=green_asg_id, LoadBalancerNames=[inactive_elb_id]))
    elif state == 'green':
        check_response(
            asg_client.attach_load_balancers(AutoScalingGroupName=blue_asg_id, LoadBalancerNames=[active_elb_id]))
        check_response(
            asg_client.attach_load_balancers(AutoScalingGroupName=green_asg_id, LoadBalancerNames=[inactive_elb_id]))
        check_response(
            asg_client.detach_load_balancers(AutoScalingGroupName=blue_asg_id, LoadBalancerNames=[inactive_elb_id]))
        check_response(
            asg_client.detach_load_balancers(AutoScalingGroupName=green_asg_id, LoadBalancerNames=[active_elb_id]))

    new_state = check_state(asg_client, blue_asg_id, active_elb_id, inactive_elb_id)
    if new_state == state:
        raise StackSwitchError('Error: stack switching failed, still in {0} state'.format(state))
    print('Old state of {0} was {1}, new state is {2}'.format(unit_name, state, new_state))


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
