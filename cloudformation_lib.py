# ================================================================
# === DESCRIPTION
# ================================================================
#
# Summary: This is a library provides a set of higher-level functions for spinning up and down AWS stacks. It is
#          designed to be used in scripts that control the creation and deletion of AWS stacks using CloudFormation.
#
#
# Version: 0.2.0
#
# Command-line arguments: None
#
# Legal stuff:
#    - Copyright (c) 2016 Jake Bennett
#    - Licensed under the MIT License - https://opensource.org/licenses/MIT

import boto3
import time
import sys
import os
from tempfile import mkstemp
from shutil import move
from botocore.exceptions import ClientError
import datetime
import subprocess

APPLICATION_NAME = 'myapp'
LOCAL_STORAGE_FILE_PATH = os.path.expanduser('~') + '/.' + APPLICATION_NAME

# =================================================================================
# ========= FUNCTIONS
# =================================================================================


def get_iam_user(session):

    iam_user = session.client('iam').get_user()
    return iam_user['User']['UserName']


def get_mfa_session(session, region):

    """
    This function gets a (Multi-Factor Authentication (MFA) token from the user via the command line and returns an
    MFA-authenticated session.
    :param session: A existing, non-MFA authenticated session. You first need to establish a plain old session before
                    getting an MFA session.
    :param region: The AWS region
    :return: A session object
    """

    done = False
    mfa_totp = None

    # Get the Multi-Factor Authentication (MFA) Time-based One Time Password (TOTP)
    while not done:
        mfa_totp = raw_input("Enter Multi-Factor Authentication Code: ")

        if (len(mfa_totp) != 6) and (not mfa_totp.isdigit()):
            print('This is not a valid MFA code. Please try again or leave blank to exit.\n')
        elif not mfa_totp:
            print('Bye')
            sys.exit(0)
        else:
            done = True

    print('Authenticating...')

    # Get the user name of user calling this code, and the account they belong to. We need this to build the
    # ARN (Amazon Resource Name) for their virtual MFA device. This keeps user names and account numbers out of source
    # code. :)
    user_name = get_iam_user(session)
    account_number = get_account_number(session)

    # Assume a role with lesser permissions when calling the API, since we're using a key. In this case, the actions
    # were doing in our script requires more permissions, as per our IAM policy, this requires MFA.
    sts = session.client('sts')
    temp_credentials = sts.get_session_token(
            SerialNumber="arn:aws:iam::" + account_number + ":mfa/" + user_name,
            TokenCode=str(mfa_totp).strip()
    )

    # Return session under the new assumed role
    return boto3.session.Session(
            aws_access_key_id=temp_credentials['Credentials']['AccessKeyId'],
            aws_secret_access_key=temp_credentials['Credentials']['SecretAccessKey'],
            region_name=region,
            aws_session_token=temp_credentials['Credentials']['SessionToken']
    )


def get_account_number(session):

    iam_user = session.client('iam').get_user()
    arn = iam_user['User']['Arn']
    return arn[13:25]


def get_aws_session(key_file_path, region):

    """
    Establishes a connection to AWS given a CSV file containing access key and secret key.
    :param key_file_path: The path to the .CSV key file containing the key
    :param region: The AWS region
    :return: A session object
    """

    if key_file_path:
        # Parse AWS key file
        key_file = open(key_file_path, "r")
        data_line = str(key_file.readlines()[1])
        access_key = data_line.split(",")[1]
        secret_key = data_line.split(",")[2]
        key_file.close()

        return boto3.session.Session(access_key, secret_key, region_name=region)
    else:
        return boto3


def get_param_from_user(input_text, validation_function, invalid_text, default_value=None):

    done = False

    while not done:
        param = raw_input(input_text)
        if (not param) and default_value:
            return default_value
        elif (not param) and (not default_value):
            print('This is a required field.')
        else:
            if not validation_function(param):
                print(invalid_text)
            else:
                return param.strip()


def get_local_var(var_name_searched):

    """
    Gets a name/value pair saved locally on the user's computer. Uses variable storage created using this library.
    :param var_name_searched: Name of the variable to lookup
    :return: The value of the variable, or None if it is not found.
    """

    if not os.path.isfile(LOCAL_STORAGE_FILE_PATH):
        return None

    with open(LOCAL_STORAGE_FILE_PATH, 'r') as local_file:
        for line in local_file:
            var_name = line.split('=')[0]
            if var_name.lower() == var_name_searched:
                return line.split('=')[1].replace('\r\n', '')

    return None


def save_local_var(var_name_searched, new_value):

    """
    Saves a name/value pair locally on the user's computer
    :param var_name_searched:
    :param new_value:
    :return:
    """
    var_updated = False

    # Create temp file
    file_handle, abs_path = mkstemp()

    # Create a temp file
    with open(abs_path, 'w+') as new_file:

        # If the local storage file already exists, loop through it and update the variable
        if os.path.isfile(LOCAL_STORAGE_FILE_PATH):
            with open(LOCAL_STORAGE_FILE_PATH, 'r') as old_file:
                for line in old_file:
                    var_name = line.split('=')[0]
                    if var_name.lower() == var_name_searched.lower():
                        new_file.write(var_name + '=' + new_value + '\r\n')
                        var_updated = True
                    else:
                        new_file.write(line)

        # If the variable wasn't in the file, than add a new line with it
        if not var_updated:
            new_file.write(var_name_searched + '=' + new_value + '\r\n')

    os.close(file_handle)

    # Remove original file if it existed
    if os.path.isfile(LOCAL_STORAGE_FILE_PATH):
        os.remove(LOCAL_STORAGE_FILE_PATH)

    # Move new file
    move(abs_path, LOCAL_STORAGE_FILE_PATH)

    return


def get_file_input(file_description, default_file, local_var_name):

    # Get the  file
    chars_from_right = 40
    pos_from_right = chars_from_right * -1
    last_file = get_local_var(local_var_name)

    if not last_file and default_file:
        last_file = default_file

    if not last_file:
        default_file_text = "[Required]"
        default_file = None
    elif len(last_file) > chars_from_right:
        default_file_text = "['..." + last_file[pos_from_right:] + "']"
        default_file = last_file
    else:
        default_file_text = '[' + last_file[pos_from_right:] + ']'
        default_file = last_file

    the_file = get_param_from_user(
            'Location of ' + file_description + ' ' + default_file_text + ': ',
            lambda param: len(param) > 5,
            'The file location you entered is not valid.',
            default_file)

    if the_file[:2] == '~/':
        the_file = the_file.replace('~/', os.path.expanduser('~') + '/')
    elif the_file[:2] == './':
        the_file = the_file.replace('./', os.path.dirname(os.path.realpath(__file__)) + '/')

    save_local_var(local_var_name, the_file)

    return the_file


def attach_iam_policy_to_ci_server(session, microservice, policy_arn):
    time.sleep(10)
    client = session.client('ec2')

    # Get all of the EC2 instances that implement the CI Server microservice.
    response = client.describe_instances(

            Filters=[
                {
                    'Name': 'tag:Microservice',
                    'Values': [microservice]
                },
                {
                    'Name': 'instance-state-name',
                    'Values':  ['running']
                }
            ]
    )

    # Get the EC2 Instance Profiles for each CI Server Instance. The Instance Profile attaches the
    # IAM Role to the EC2 Instance
    instances_profiles = []
    for reservation in response['Reservations']:
        for instance in reservation['Instances']:
            instances_profiles.append(instance['IamInstanceProfile']['Arn'])

    # Make the list of instance profiles unique
    instances_profiles = list(set(instances_profiles))

    # Loop through the instance profiles, get the associated IAM role, and attach the policy to it.
    iam = session.client('iam')
    for profile_arn in instances_profiles:
        friendly_profile_name = profile_arn[profile_arn.find("/")+1:]
        instance_profile = iam.get_instance_profile(InstanceProfileName=friendly_profile_name)
        instance_role = instance_profile['InstanceProfile']['Roles'][0]['RoleName']

        # Attach the proxy IAM policy to EC2 Instance Profile Role
        iam.attach_role_policy(
                RoleName=instance_role,
                PolicyArn=policy_arn
        )


def create_policy(session, iam_policy_name, account_number, policy_body, policy_description):

    iam = session.client('iam')

    # If the policy already exists, delete it and all it's versions. However, if there IAM groups, roles or users
    # attached to the policy, we'll let the API call fail. IAM entities should be removed manually, not automatically.
    if policy_exists(iam, iam_policy_name):
        delete_policy(iam, account_number, iam_policy_name)

    # Create the IAM policy
    iam.create_policy(
            PolicyName=iam_policy_name,
            PolicyDocument=policy_body,
            Description=policy_description
    )

    return


def policy_exists(client, policy_name):

    iam_policies = client.list_policies(Scope='Local')
    policy_names = [p['PolicyName'] for p in iam_policies['Policies']]
    return policy_name in policy_names


def delete_policy(session, account_number, policy_name):

    client = session.client('iam')
    policy_arn = get_policy_arn(account_number, policy_name)

    # Confirm that policy exists before trying to delete it's versions (which will cause an error)
    response = client.list_policies(Scope='Local', OnlyAttached=False)
    policy_names = [policy['PolicyName'] for policy in response['Policies']]
    if policy_name not in policy_names:
        return

    # Delete any older versions of this policy
    policy_versions = client.list_policy_versions(PolicyArn=policy_arn)['Versions']
    for version in policy_versions:
        if not version['IsDefaultVersion']:
            client.delete_policy_version(PolicyArn=policy_arn, VersionId=version['VersionId'])

    # Delete any roles (e.g. instance roles) the policy is attached to
    entities = client.list_entities_for_policy(
            PolicyArn=policy_arn,
            EntityFilter='Role'
    )

    for policy_group in entities['PolicyRoles']:
        client.detach_role_policy(
                RoleName=policy_group['RoleName'],
                PolicyArn=policy_arn
        )

    # Delete policy
    try:
        client.delete_policy(PolicyArn=policy_arn)
    except Exception, e:
        # If there are IAM groups or users attached to this policy, then an error will be thrown.
        print(str(e))
        sys.exit(55)


def get_policy_arn(account_number, policy_name):
    return 'arn:aws:iam::' + account_number + ':policy/' + policy_name


def wait_for_stack_to_complete(session, stack_id):

    stack_outputs = None
    max_wait_secs = 10 * 60  # 10 minutes
    sleep_time_secs = 1
    max_iterations = max_wait_secs / sleep_time_secs
    num_of_iterations = 0

    done = False
    client = session.client('cloudformation')
    successfully_completed_statuses = ['CREATE_COMPLETE', 'DELETE_COMPLETE', 'UPDATE_COMPLETE']
    failed_statuses = ['CREATE_FAILED', 'ROLLBACK_IN_PROGRESS', 'ROLLBACK_FAILED', 'ROLLBACK_COMPLETE', 'DELETE_FAILED',
                       'UPDATE_ROLLBACK_IN_PROGRESS', 'UPDATE_ROLLBACK_FAILED', 'UPDATE_ROLLBACK_COMPLETE',
                       'UPDATE_ROLLBACK_COMPLETE_CLEANUP_IN_PROGRESS']
    in_progress_statuses = ['CREATE_IN_PROGRESS', 'DELETE_IN_PROGRESS', 'UPDATE_IN_PROGRESS',
                            'UPDATE_COMPLETE_CLEANUP_IN_PROGRESS']

    while not done:

        if not stack_exists(session, stack_id):
            return

        try:
            response = client.describe_stacks(StackName=stack_id)
            stack_status = response['Stacks'][0]['StackStatus']
        except ClientError, e:
            if 'does not exist' in str(e):
                return

        if stack_status in successfully_completed_statuses:
            done = True
            if 'Outputs' in response['Stacks'][0]:
                stack_outputs = response['Stacks'][0]['Outputs']
            else:
                stack_outputs = None

        elif stack_status in failed_statuses:
            print('Stack creation failed. Status is "' + stack_status + '". Review the Events for this ' +
                  'CloudFormation stack in the AWS Console to see what failed.')
            sys.exit(56)

        elif num_of_iterations > max_iterations:
            print('Stack creation timed-out. Login into the AWS console to check the status.')
            sys.exit(56)

        elif stack_status in in_progress_statuses:
            num_of_iterations += 1
            time.sleep(sleep_time_secs)

        else:
            raise KeyError("Unknown stack status '" + stack_status + "'")

    return stack_outputs


def stack_exists(session, stack_name):

    client = session.client('cloudformation')

    try:
        client.describe_stacks(StackName=stack_name)
    except ClientError:
        return False

    return True


def delete_line_from_file(file_path, text_to_search):

    the_file = open(file_path)
    output = []
    for line in the_file:
        if text_to_search in line:
            pass
        else:
            output.append(line)
    the_file.close()
    the_file = open(file_path, 'w')
    the_file.writelines(output)
    the_file.close()


def wait_for_volume_to_complete(session, volume_id):

    max_wait_secs = 60 * 5  # 10 minutes
    sleep_time_secs = 1
    max_iterations = max_wait_secs / sleep_time_secs
    num_of_iterations = 0

    done = False
    client = session.client('ec2')
    successfully_completed_statuses = ['available', 'deleted']
    in_progress_statuses = ['creating', 'deleting']
    failed_statuses = ['in-use', 'error']

    while not done:

        try:
            response = client.describe_volumes(VolumeIds=[volume_id])
            status = response['Volumes'][0]['State']
        except ClientError, e:
            if 'does not exist.' in str(e):
                return

        if status in successfully_completed_statuses:
            done = True

        elif status in failed_statuses:
            print('Volume creation failed. Status is "' + status + '". Review the Events for this ' +
                  'volume in the AWS Console to see what failed.')
            sys.exit(66)

        elif num_of_iterations > max_iterations:
            print('Volume creation timed-out. Login into the AWS console to check the status.')
            sys.exit(68)

        elif status in in_progress_statuses:
            num_of_iterations += 1
            time.sleep(sleep_time_secs)

        else:
            raise KeyError("Unknown stack status '" + status + "'")

    return


def create_volume(session, volume_name, volume_size_gb, availability_zone, microservice, build_env):

    # If volume already exists, then exit function. We don't want to create another one.
    volume_id = get_volume_id(session, volume_name)
    if volume_id:
        return volume_id

    # Then create volume
    print('Creating volume...')
    client = session.client('ec2')
    response = client.create_volume(
            Size=volume_size_gb,
            AvailabilityZone=availability_zone,
            VolumeType='standard',
            Encrypted=False
    )

    volume_id = response['VolumeId']
    wait_for_volume_to_complete(session, volume_id)

    # Tag the volume
    client.create_tags(
            Resources=[volume_id],
            Tags=[
                {
                    'Key': 'Name',
                    'Value': volume_name
                },
                {
                    'Key': 'Microservice',
                    'Value': microservice
                },
                {
                    'Key': 'Environment',
                    'Value': build_env
                },
            ]
    )

    return volume_id


def get_volume_id(session, volume_name):

    """
    Returns the id of volume given the Name tag value. Returns None if volume doesn't exist.
    :param session:
    :param volume_name:
    :return:
    """

    client = session.client('ec2')

    response = client.describe_volumes(
            Filters=[
                {
                    'Name': 'tag:Name',
                    'Values': [
                        volume_name,
                    ]
                }
            ]
    )

    if len(response['Volumes']) > 1:
        raise LookupError("More than 1 volumes named '" + volume_name + "' exist. This isn't normal.")
    elif len(response['Volumes']) == 0:
        return None
    else:
        return response['Volumes'][0]['VolumeId']


def delete_volume(session, volume_name):

    # If the volume exists, then delete it

    volume_id = get_volume_id(session, volume_name)
    if volume_id:
        client = session.client('ec2')
        client.delete_volume(VolumeId=volume_id)
        wait_for_volume_to_complete(session, volume_id)


def get_subnet_az(session, subnet_id):

    """
    Gets a subnet's availability zone based on subnet ID. Returns None if not subnet exists with the ID.
    :param session:
    :param subnet_id:
    :return:
    """

    client = session.client('ec2')

    response = client.describe_subnets(
            SubnetIds=[
                subnet_id,
            ]
    )

    return response['Subnets'][0]['AvailabilityZone']


def get_microservice_key_pair(session, microservice):

    """
    This function creates a new key pair and ensures that there is only one key pair active for a microservice
    at any one-time. If an existing key pair exists (for just this microservice) then it will be deleted first.
    :param session:
    :param microservice:
    :return:
    """

    # Does a key pair exist for this microservice?
    # Loop through EC2 instances and get key pairs in-use from the EC2 tag
    client = session.client('ec2')
    response = client.describe_instances(
            Filters=[
                {
                    'Name': 'tag:Microservice',
                    'Values': [microservice]
                },
                {
                    'Name': 'instance-state-name',
                    'Values': ['running']
                }
            ]
    )

    # If there are no running instances, then let's get the key pair name the AWS Key pairs
    if len(response['Reservations']) == 0:
        response = client.describe_key_pairs(
                Filters=[
                    {
                        'Name': 'key-name',
                        'Values': ['EC2Key-CIService-*']
                     }
                ]
        )

        # If the is one key pair, then use it
        if len(response['KeyPairs']) == 1:
            return response['KeyPairs'][0]['KeyName']
        else:
            return None

    # Get one list of the EC2 instances, regardless of their reservation.
    instances = []
    for reservation in response['Reservations']:
        instances.extend(reservation['Instances'])

    # Get the 'KeyPair' tag values for the EC2 instances. This tells us all of the KeyPairs used by the EC2 instances.
    key_pairs = []
    for instance in instances:
        tags = [item['Value'] for item in instance['Tags'] if item['Key'] == 'KeyPair']
        key_pairs.extend(tags)

    # Get a list of unique Key Pairs used by the EC2 Instances. We want to know how many different key pairs are in-use.
    existing_keys_pairs = list(set(key_pairs))

    # If there are multiple key pairs used by this microservice, then it's an error condition. There should only be one.
    if len(existing_keys_pairs) > 1:
        raise KeyError(
                "More than one key pair was found associated with the EC2 instances for this microservice." +
                "This is not a normal condition. Please review the key pairs and EC2 instances in the AWS " +
                "console and fix the issue. " +
                "Microservice: " + microservice + ". " +
                "Key pairs: " + str(existing_keys_pairs)
        )

    # If there are no EC2 instances that matched our filter, return null
    if len(existing_keys_pairs) == 0:
        return None

    # If there is an existing key pair that this being used by any EC2 instances *outside* of this service, then it's
    # an error. We can't risk deleting a key that is used to gain access to host for an unknown service.
    rogue_instances = get_rogue_instances_using_keypair(session, existing_keys_pairs[0], microservice)
    if rogue_instances:
        raise KeyError(
                "There is one or more EC2 instances outside of the '" + microservice + "' microservice that are  " +
                "using the the key pair associated with this microservice. This is a non-normal condition. We can " +
                "have only 1 key pair per microservice. Please fix the issue in the AWS console before proceededing." +
                "Microservice: " + microservice + ". " +
                "Rogue EC2 instances: " + str(rogue_instances)
        )

    return existing_keys_pairs[0]


def get_rogue_instances_using_keypair(session, key_pair, microservice):

    """
    This function returns the IDs of EC2 using the key pair designated for this microservice, but are not themselves
    part of this microservice.
    :param session:
    :param key_pair:
    :param microservice:
    :return:
    """

    client = session.client('ec2')
    response = client.describe_instances(
            Filters=[
                {
                    'Name': 'tag:KeyPair',
                    'Values': [key_pair]
                },
                {
                    'Name': 'instance-state-name',
                    'Values': ['running']
                }
            ]
    )

    # Get one list of the EC2 instances, regardless of their reservation.
    instances = []
    for reservation in response['Reservations']:
        instances.extend(reservation['Instances'])

    # Loop through each instance, and check for a Microservice tag that differs from our microservice.
    rogue_instances = []
    microservice_tag_found = False
    for instance in instances:

        # Check the instances's tags to see if there is a Microservice tag that differs from our microservice.
        for tag in instance['Tags']:
            if tag['Key'] == 'Microservice':
                if tag['Value'] != microservice:
                    rogue_instances.append(instance['InstanceId'])

                microservice_tag_found = True
                break

        # Also, check for EC2 instances using our Key Pair that don't have a Microservices tag. These are rogue too.
        if not microservice_tag_found:
            rogue_instances.append(instance['InstanceId'])

        # Reset our flag
        microservice_tag_found = False

    return rogue_instances


def create_key_pair(session, local_key_dir, microservice):

    # Generate key pair
    key_name = 'EC2Key-' + microservice + '-' + datetime.datetime.now().strftime("%Y-%m-%d-%H%M%S")
    client = session.client('ec2')
    key_pair = client.create_key_pair(KeyName=key_name)

    # Save private key locally
    private_key_file_name = key_name + '.pem'
    private_key_file = open(local_key_dir + '/' + private_key_file_name, 'w')
    private_key_file.write(key_pair['KeyMaterial'])
    private_key_file.close()

    # Lock down permissions on the key
    bash_command = "chmod 700 " + local_key_dir + '/' + private_key_file_name
    subprocess.Popen(bash_command.split(), stdout=subprocess.PIPE)

    return key_name


def fill_template_from_dict(template_path, variable_value_dict):

    template_body = ''
    replacement_variables = [key for key in variable_value_dict]

    with open(template_path, 'r') as template_file:
        line = template_file.read()
        for var in replacement_variables:
            if '${' + var + '}' in line:
                line = line.replace('${' + var + '}', variable_value_dict[var])
        template_body += line

    return template_body


def fill_template_from_properties(template_path, properties_file_path):

    template_body = ''
    variables = {}

    properties_file = open(properties_file_path, 'r')
    for line in properties_file.readlines():
        if line.lstrip()[:1] == "#":
            pass
        elif line.find('=') > 0:
            variable_name = line[:line.find('=')]
            variable_value = line[line.find('=') + 1:].replace('\n', '')
            variables[variable_name] = variable_value

    variable_names = [key for key in variables]

    template_file = open(template_path, 'r')
    for line in template_file.readlines():
        for var in variable_names:
            if '${' + var + '}' in line:
                line = line.replace('${' + var + '}', variables[var])
        template_body += line

    return template_body


def empty_bucket(session, bucket_name):

    client = session.client('s3')

    # Check if the bucket exists
    response = client.list_buckets()
    buckets = [bucket['Name'] for bucket in response['Buckets']]
    if bucket_name not in buckets:
        return

    # Delete all of the objects in the bucket
    try:
        response = client.list_objects(Bucket=bucket_name)
        if 'Contents' in response:
            for obj in response['Contents']:
                client.delete_object(Bucket=bucket_name, Key=obj['Key'])
    except ClientError, e:
        if 'The specified bucket does not exist' in str(e):
            # A strange condition occurs sometimes when the bucket exists, but errors out when something is put into it
            return
        else:
            raise


def upload_file_to_s3(session, file_path, bucket_name, bucket_key):

    """
    Uploads a stack file to S3
    :param session:
    :param file_path:
    :param bucket_name:
    :param bucket_key:
    :return:
    """

    # Upload private key to S3
    s3 = session.resource('s3')
    s3.meta.client.upload_file(file_path, bucket_name, bucket_key)


def upload_template_to_s3(session, template_file, properties_file, bucket_name, bucket_key):

    """
    Uploads a template file to s3 that contains variables that should be replaced with values defined in a properties file
    :param session:
    :param template_file:
    :param properties_file:
    :param bucket_name:
    :param bucket_key:
    :return:
    """
    
    # Upload git config to S3
    config_file = fill_template_from_properties(template_file, properties_file)
    client = session.client('s3')
    client.put_object(
            Key=bucket_key,
            ACL='private',
            Bucket=bucket_name,
            Body=config_file
    )
