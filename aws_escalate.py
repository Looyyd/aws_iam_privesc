# Original file from https://github.com/RhinoSecurityLabs/Security-Research/blob/master/tools/aws-pentest-tools/aws_escalate.py . Improved upon with new methods and ported to BlackArch Linux

#!/usr/bin/env python3
from __future__ import print_function
import boto3, argparse, os, sys, json, time
from botocore.exceptions import ClientError

def main(args):
    access_key_id = args.access_key_id
    secret_access_key = args.secret_key
    session_token = args.session_token

    if args.access_key_id is None or args.secret_key is None:
        print('IAM keys not passed in as arguments, enter them below:')
        access_key_id = input('  Access Key ID: ')
        secret_access_key = input('  Secret Access Key: ')
        session_token = input('  Session Token (Leave blank if none): ')
        if session_token.strip() == '':
            session_token = None

    # Begin permissions enumeration
    current_user = None
    users = []
    client = boto3.client(
        'iam',
        aws_access_key_id=access_key_id,
        aws_secret_access_key=secret_access_key,
        aws_session_token=session_token
    )
    if args.all_users is True:
        response = client.list_users()
        for user in response['Users']:
            users.append({'UserName': user['UserName'], 'Permissions': {'Allow': {}, 'Deny': {}}})
        while 'IsTruncated' in response and response['IsTruncated'] is True:
            response = client.list_users(
                Marker=response['Marker']
            )
            for user in response['Users']:
                users.append({'UserName': user['UserName'], 'Permissions': {'Allow': {}, 'Deny': {}}})
    elif args.user_name is not None:
        users.append({'UserName': args.user_name, 'Permissions': {'Allow': {}, 'Deny': {}}})
    else:
        current_user = client.get_user()['User']
        current_user = {
            'UserName': current_user['UserName'],
            'Permissions': {
                'Allow': {},
                'Deny': {}
            }
        }
        users.append(current_user)
    print('Collecting policies for {} users...'.format(len(users)))
    for user in users:
        user['Groups'] = []
        user['Policies'] = []
        try:
            policies = []

            ## Get groups that the user is in
            try:
                res = client.list_groups_for_user(
                    UserName=user['UserName']
                )
                user['Groups'] = res['Groups']
                while 'IsTruncated' in res and res['IsTruncated'] is True:
                    res = client.list_groups_for_user(
                        UserName=user['UserName'],
                        Marker=groups['Marker']
                    )
                    user['Groups'] += res['Groups']
            except Exception as e:
                print('List groups for user failed: {}'.format(e))
                user['PermissionsConfirmed'] = False

            ## Get inline and attached group policies
            for group in user['Groups']:
                group['Policies'] = []
                ## Get inline group policies
                try:
                    res = client.list_group_policies(
                        GroupName=group['GroupName']
                    )
                    policies = res['PolicyNames']
                    while 'IsTruncated' in res and res['IsTruncated'] is True:
                        res = client.list_group_policies(
                            GroupName=group['GroupName'],
                            Marker=res['Marker']
                        )
                        policies += res['PolicyNames']
                except Exception as e:
                    print('List group policies failed: {}'.format(e))
                    user['PermissionsConfirmed'] = False
                # Get document for each inline policy
                for policy in policies:
                    group['Policies'].append({ # Add policies to list of policies for this group
                        'PolicyName': policy
                    })
                    try:
                        document = client.get_group_policy(
                            GroupName=group['GroupName'],
                            PolicyName=policy
                        )['PolicyDocument']
                    except Exception as e:
                        print('Get group policy failed: {}'.format(e))
                        user['PermissionsConfirmed'] = False
                    user = parse_document(document, user)

                ## Get attached group policies
                attached_policies = []
                try:
                    res = client.list_attached_group_policies(
                        GroupName=group['GroupName']
                    )
                    attached_policies = res['AttachedPolicies']
                    while 'IsTruncated' in res and res['IsTruncated'] is True:
                        res = client.list_attached_group_policies(
                            GroupName=group['GroupName'],
                            Marker=res['Marker']
                        )
                        attached_policies += res['AttachedPolicies']
                    group['Policies'] += attached_policies
                except Exception as e:
                    print('List attached group policies failed: {}'.format(e))
                    user['PermissionsConfirmed'] = False
                user = parse_attached_policies(client, attached_policies, user)

            ## Get inline user policies
            policies = []
            if 'Policies' not in user:
                user['Policies'] = []
            try:
                res = client.list_user_policies(
                    UserName=user['UserName']
                )
                policies = res['PolicyNames']
                while 'IsTruncated' in res and res['IsTruncated'] is True:
                    res = client.list_user_policies(
                        UserName=user['UserName'],
                        Marker=res['Marker']
                    )
                    policies += res['PolicyNames']
                for policy in policies:
                    user['Policies'].append({
                        'PolicyName': policy
                    })
            except Exception as e:
                print('List user policies failed: {}'.format(e))
                user['PermissionsConfirmed'] = False
            # Get document for each inline policy
            for policy in policies:
                try:
                    document = client.get_user_policy(
                        UserName=user['UserName'],
                        PolicyName=policy
                    )['PolicyDocument']
                except Exception as e:
                    print('Get user policy failed: {}'.format(e))
                    user['PermissionsConfirmed'] = False
                user = parse_document(document, user)
            ## Get attached user policies
            attached_policies = []
            try:
                res = client.list_attached_user_policies(
                    UserName=user['UserName']
                )
                attached_policies = res['AttachedPolicies']
                while 'IsTruncated' in res and res['IsTruncated'] is True:
                    res = client.list_attached_user_policies(
                        UserName=user['UserName'],
                        Marker=res['Marker']
                    )
                    attached_policies += res['AttachedPolicies']
                user['Policies'] += attached_policies
            except Exception as e:
                print('List attached user policies failed: {}'.format(e))
                user['PermissionsConfirmed'] = False
            user = parse_attached_policies(client, attached_policies, user)
            user.pop('Groups', None)
            user.pop('Policies', None)
        except Exception as e:
            print('Error, skipping user {}:\n{}'.format(user['UserName'], e))
        print('  {}... done!'.format(user['UserName']))

    print('  Done.\n')


    escalation_methods = {
        # Api Gateway
        # https://cloud.hacktricks.xyz/pentesting-cloud/aws-security/aws-privilege-escalation/aws-apigateway-privesc
        "GenerateAPIKeys": [
            "apigateway:POST"
        ],
        "GetGeneratedAPIKeys": [
            "apigateway:GET"
        ],
        "ChangeAPIPolicy": [
            "apigateway:UpdateRestApiPolicy",
            "apigateway:PATCH"
        ],
        # skipped this because "Need Testing"
        # apigateway:PutIntegration, apigateway:CreateDeployment, iam:PassRole

        "AccessPrivateAPI": [
            "apigateway:UpdateVpcLink"
        ],

        # Codebuild

        "CreateCodebuildWithExistingIP": [
            "iam:PassRole",
            "codebuild:CreateProject",
            # Either of these works:
            ["codebuild:StartBuild", "codebuild:StartBuildBatch"]
        ],


        "CreateNewPolicyVersion": [
            "iam:CreatePolicyVersion"
        ],
        "SetExistingDefaultPolicyVersion": [
            "iam:SetDefaultPolicyVersion"
        ],
        "CreateEC2WithExistingIP": [
            "iam:PassRole",
            "ec2:RunInstances"
        ],
        "CreateAccessKey": [
            "iam:CreateAccessKey"
        ],
        "CreateLoginProfile": [
            "iam:CreateLoginProfile"
        ],
        "UpdateLoginProfile": [
            "iam:UpdateLoginProfile"
        ],
        "AttachUserPolicy": [
            "iam:AttachUserPolicy"
        ],
        "AttachGroupPolicy": [
            "iam:AttachGroupPolicy"
        ],
        "AttachRolePolicy": [
            "iam:AttachRolePolicy",
            "sts:AssumeRole"
        ],
        "PutUserPolicy": [
            "iam:PutUserPolicy"
        ],
        "PutGroupPolicy": [
            "iam:PutGroupPolicy"
        ],
        "PutRolePolicy": [
            "iam:PutRolePolicy",
            "sts:AssumeRole"
        ],
        "AddUserToGroup": [
            "iam:AddUserToGroup"
        ],
        "UpdateRolePolicyToAssumeIt": [
            "iam:UpdateAssumeRolePolicy",
            "sts:AssumeRole"
        ],
        "PassExistingRoleToNewLambdaThenInvoke": [
            "iam:PassRole",
            "lambda:CreateFunction",
            "lambda:InvokeFunction"
        ],
        "PassExistingRoleToNewLambdaThenTriggerWithNewDynamo": [
            "iam:PassRole",
            "lambda:CreateFunction",
            "lambda:CreateEventSourceMapping",
            "dynamodb:CreateTable",
            "dynamodb:PutItem"
        ],
        "PassExistingRoleToNewLambdaThenTriggerWithExistingDynamo": [
            "iam:PassRole",
            "lambda:CreateFunction",
            "lambda:CreateEventSourceMapping"
        ],
        "PassExistingRoleToNewGlueDevEndpoint": [
            "iam:PassRole",
            "glue:CreateDevEndpoint"
        ],
        "UpdateExistingGlueDevEndpoint": [
            "glue:UpdateDevEndpoint"
        ],
        "EditExistingLambdaFunctionWithRole": [
            "lambda:UpdateFunctionCode"
        ],
        "CreateCodestarProjectFromTemplate": [
            "codestar:CreateProjectFromTemplate"
        ],
        "PassRoleToNewCodestarProject": [
            "codestar:CreateProject",
            "iam:PassRole"
        ],
        "AssociateTeammemberToCodestarProject": [
            "codestar:CreateProject",
            "sagemaker:CreatePresignedNotebookInstanceUrl"
        ],
        "GetFederationTokenID": [
            "sts:GetFederationToken"
        ]
    }  


    # Extract all permissions from the combinations
    all_perms = set()
    for combination in escalation_methods.values():
        for perm in combination:
            permissions_to_add = array_or_string_to_array_of_strings(perm)
            for permission in permissions_to_add:
                all_perms.add(permission)

    import re
    for user in users:
        print('User: {}'.format(user['UserName']))
        checked_perms = {'Allow': {}, 'Deny': {}}
        # Preliminary check to see if these permissions have already been enumerated in this session
        if 'Permissions' in user and 'Allow' in user['Permissions']:
            # Are they an admin already?
            if '*' in user['Permissions']['Allow'] and user['Permissions']['Allow']['*'] == ['*']:
                user['CheckedMethods'] = {'admin': {}, 'Confirmed':{}, 'Potential': {}}
                print('  Already an admin!\n')
                continue
            for perm in all_perms:
                for effect in ['Allow', 'Deny']:
                    if perm in user['Permissions'][effect]:
                        checked_perms[effect][perm] = user['Permissions'][effect][perm]
                    else:
                        for user_perm in user['Permissions'][effect].keys():
                            if '*' in user_perm:
                                pattern = re.compile(user_perm.replace('*', '.*'))
                                if pattern.search(perm) is not None:
                                    checked_perms[effect][perm] = user['Permissions'][effect][user_perm]

        # Ditch each escalation method that has been confirmed not to be possible
        checked_methods = {
            'Potential': [],
            'Confirmed': []
        }

        for method in escalation_methods.keys():
            potential = True
            confirmed = True
            permissions = escalation_methods[method]  # Get the permissions for the method

            for permission_options in permissions:
                permissions_options_to_check = array_or_string_to_array_of_strings(permission_options)

                option_confirmed = False
                option_potential = False
                for p in permissions_options_to_check:
                    if p in checked_perms['Allow'] and p not in checked_perms['Deny']:
                        option_potential = True
                        if checked_perms['Allow'][p] == ['*']:
                            option_confirmed = True

                if not option_confirmed:
                    confirmed = False
                if not option_potential:  # If no potential, then no need to continue checking
                    potential = confirmed = False
                    break


            if confirmed:
                print('  CONFIRMED: {}\n'.format(method))
                checked_methods['Confirmed'].append(method)
            elif potential:
                print('  POTENTIAL: {}\n'.format(method))
                checked_methods['Potential'].append(method)

        user['CheckedMethods'] = checked_methods

        if not checked_methods['Potential'] and not checked_methods['Confirmed']:
            print('  No methods possible.\n')



    now = time.time()

    file = open('all_user_privesc_scan_results_{}.csv'.format(now), 'w+')
    for user in users:
        if 'admin' in user['CheckedMethods']:
            file.write(',{} (Admin)'.format(user['UserName']))
        else:
            file.write(',{}'.format(user['UserName']))
    file.write('\n')
    for method in escalation_methods.keys():
        file.write('{},'.format(method))
        for user in users:
            if method in user['CheckedMethods']['Confirmed']:
                file.write('Confirmed,')
            elif method in user['CheckedMethods']['Potential']:
                file.write('Potential,')
            else:
                file.write(',')
        file.write('\n')
    file.close()
    print('Privilege escalation check completed. Results stored to ./all_user_privesc_scan_results_{}.csv'.format(now))

def array_or_string_to_array_of_strings(perm):
    if isinstance(perm, str):
        return [perm]  # Single option
    else:
        return perm  # Multiple choices


# https://stackoverflow.com/a/24893252
def remove_empty_from_dict(d):
    if type(d) is dict:
        return dict((k, remove_empty_from_dict(v)) for k, v in d.items() if v and remove_empty_from_dict(v))
    elif type(d) is list:
        return [remove_empty_from_dict(v) for v in d if v and remove_empty_from_dict(v)]
    else:
        return d

# Pull permissions from each policy document
def parse_attached_policies(client, attached_policies, user):
    for policy in attached_policies:
        document = get_attached_policy(client, policy['PolicyArn'])
        if document is False:
            user['PermissionsConfirmed'] = False
        else:
            user = parse_document(document, user)
    return user

# Get the policy document of an attached policy
def get_attached_policy(client, policy_arn):
    try:
        policy = client.get_policy(
            PolicyArn=policy_arn
        )['Policy']
        version = policy['DefaultVersionId']
        can_get = True
    except Exception as e:
        print('Get policy failed: {}'.format(e))
        return False

    try:
        if can_get is True:
            document = client.get_policy_version(
                PolicyArn=policy_arn,
                VersionId=version
            )['PolicyVersion']['Document']
            return document
    except Exception as e:
        print('Get policy version failed: {}'.format(e))
        return False

# Loop permissions and the resources they apply to
def parse_document(document, user):
    if type(document['Statement']) is dict:
        document['Statement'] = [document['Statement']]
    for statement in document['Statement']:
        if statement['Effect'] == 'Allow':
            if 'Action' in statement and type(statement['Action']) is list: # Check if the action is a single action (str) or multiple (list)
                statement['Action'] = list(set(statement['Action'])) # Remove duplicates to stop the circular reference JSON error
                for action in statement['Action']:
                    if action in user['Permissions']['Allow']:
                        if type(statement['Resource']) is list:
                            user['Permissions']['Allow'][action] += statement['Resource']
                        else:
                            user['Permissions']['Allow'][action].append(statement['Resource'])
                    else:
                        if type(statement['Resource']) is list:
                            user['Permissions']['Allow'][action] = statement['Resource']
                        else:
                            user['Permissions']['Allow'][action] = [statement['Resource']]
                    user['Permissions']['Allow'][action] = list(set(user['Permissions']['Allow'][action])) # Remove duplicate resources
            elif 'Action' in statement and type(statement['Action']) is str:
                if statement['Action'] in user['Permissions']['Allow']:
                    if type(statement['Resource']) is list:
                        user['Permissions']['Allow'][statement['Action']] += statement['Resource']
                    else:
                        user['Permissions']['Allow'][statement['Action']].append(statement['Resource'])
                else:
                    if type(statement['Resource']) is list:
                        user['Permissions']['Allow'][statement['Action']] = statement['Resource']
                    else:
                        user['Permissions']['Allow'][statement['Action']] = [statement['Resource']] # Make sure that resources are always arrays
                user['Permissions']['Allow'][statement['Action']] = list(set(user['Permissions']['Allow'][statement['Action']])) # Remove duplicate resources
            if 'NotAction' in statement and type(statement['NotAction']) is list: # NotAction is reverse, so allowing a NotAction is denying that action basically
                statement['NotAction'] = list(set(statement['NotAction'])) # Remove duplicates to stop the circular reference JSON error
                for not_action in statement['NotAction']:
                    if not_action in user['Permissions']['Deny']:
                        if type(statement['Resource']) is list:
                            user['Permissions']['Deny'][not_action] += statement['Resource']
                        else:
                            user['Permissions']['Deny'][not_action].append(statement['Resource'])
                    else:
                        if type(statement['Resource']) is list:
                            user['Permissions']['Deny'][not_action] = statement['Resource']
                        else:
                            user['Permissions']['Deny'][not_action] = [statement['Resource']]
                    user['Permissions']['Deny'][not_action] = list(set(user['Permissions']['Deny'][not_action])) # Remove duplicate resources
            elif 'NotAction' in statement and type(statement['NotAction']) is str:
                if statement['NotAction'] in user['Permissions']['Deny']:
                    if type(statement['Resource']) is list:
                        user['Permissions']['Deny'][statement['NotAction']] += statement['Resource']
                    else:
                        user['Permissions']['Deny'][statement['NotAction']].append(statement['Resource'])
                else:
                    if type(statement['Resource']) is list:
                        user['Permissions']['Deny'][statement['NotAction']] = statement['Resource']
                    else:
                        user['Permissions']['Deny'][statement['NotAction']] = [statement['Resource']] # Make sure that resources are always arrays
                user['Permissions']['Deny'][statement['NotAction']] = list(set(user['Permissions']['Deny'][statement['NotAction']])) # Remove duplicate resources
        if statement['Effect'] == 'Deny':
            if 'Action' in statement and type(statement['Action']) is list:
                statement['Action'] = list(set(statement['Action'])) # Remove duplicates to stop the circular reference JSON error
                for action in statement['Action']:
                    if action in user['Permissions']['Deny']:
                        if type(statement['Resource']) is list:
                            user['Permissions']['Deny'][action] += statement['Resource']
                        else:
                            user['Permissions']['Deny'][action].append(statement['Resource'])
                    else:
                        if type(statement['Resource']) is list:
                            user['Permissions']['Deny'][action] = statement['Resource']
                        else:
                            user['Permissions']['Deny'][action] = [statement['Resource']]
                    user['Permissions']['Deny'][action] = list(set(user['Permissions']['Deny'][action])) # Remove duplicate resources
            elif 'Action' in statement and type(statement['Action']) is str:
                if statement['Action'] in user['Permissions']['Deny']:
                    if type(statement['Resource']) is list:
                        user['Permissions']['Deny'][statement['Action']] += statement['Resource']
                    else:
                        user['Permissions']['Deny'][statement['Action']].append(statement['Resource'])
                else:
                    if type(statement['Resource']) is list:
                        user['Permissions']['Deny'][statement['Action']] = statement['Resource']
                    else:
                        user['Permissions']['Deny'][statement['Action']] = [statement['Resource']] # Make sure that resources are always arrays
                user['Permissions']['Deny'][statement['Action']] = list(set(user['Permissions']['Deny'][statement['Action']])) # Remove duplicate resources
            if 'NotAction' in statement and type(statement['NotAction']) is list: # NotAction is reverse, so allowing a NotAction is denying that action basically
                statement['NotAction'] = list(set(statement['NotAction'])) # Remove duplicates to stop the circular reference JSON error
                for not_action in statement['NotAction']:
                    if not_action in user['Permissions']['Allow']:
                        if type(statement['Resource']) is list:
                            user['Permissions']['Allow'][not_action] += statement['Resource']
                        else:
                            user['Permissions']['Allow'][not_action].append(statement['Resource'])
                    else:
                        if type(statement['Resource']) is list:
                            user['Permissions']['Allow'][not_action] = statement['Resource']
                        else:
                            user['Permissions']['Allow'][not_action] = [statement['Resource']]
                    user['Permissions']['Allow'][not_action] = list(set(user['Permissions']['Allow'][not_action])) # Remove duplicate resources
            elif 'NotAction' in statement and type(statement['NotAction']) is str:
                if statement['NotAction'] in user['Permissions']['Allow']:
                    if type(statement['Resource']) is list:
                        user['Permissions']['Allow'][statement['NotAction']] += statement['Resource']
                    else:
                        user['Permissions']['Allow'][statement['NotAction']].append(statement['Resource'])
                else:
                    if type(statement['Resource']) is list:
                        user['Permissions']['Allow'][statement['NotAction']] = statement['Resource']
                    else:
                        user['Permissions']['Allow'][statement['NotAction']] = [statement['Resource']] # Make sure that resources are always arrays
                user['Permissions']['Allow'][statement['NotAction']] = list(set(user['Permissions']['Allow'][statement['NotAction']])) # Remove duplicate resources
    return user

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='This script will fetch permissions for a set of users and then scan for permission misconfigurations to see what privilege escalation methods are possible. Available attack paths will be output to a .csv file in the same directory.')
    parser.add_argument('--all-users', required=False, default=False, action='store_true', help='Run this module against every user in the account.')
    parser.add_argument('--user-name', required=False, default=None, help='A single username of a user to run this module against. By default, the user to which the active AWS keys belong to will be used.')
    parser.add_argument('--access-key-id', required=False, default=None, help='The AWS access key ID to use for authentication.')
    parser.add_argument('--secret-key', required=False, default=None, help='The AWS secret access key to use for authentication.')
    parser.add_argument('--session-token', required=False, default=None, help='The AWS session token to use for authentication, if there is one.')

    args = parser.parse_args()
    main(args)
