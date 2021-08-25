# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of this
# software and associated documentation files (the "Software"), to deal in the Software
# without restriction, including without limitation the rights to use, copy, modify,
# merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
# INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
# PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
# HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
# SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.


# !/usr/bin/env python

from __future__ import print_function
import time
import sys
import json
import boto3
import botocore
from botocore.vendored import requests
from botocore.exceptions import ClientError

# '''AWS Organizations Create Account and Provision Resources via CloudFormation
#
# This module creates a new account using Organizations, then calls CloudFormation
# to deploy baseline resources within that account via a local tempalte file.
#
# '''

__version__ = '1.1'
__author__ = 'elamaras@', 'kkdaws@'
__email__ = 'elamaras@'


def get_client(service):
    """Gets boto3 client info."""
    client = boto3.client(service)
    return client


def create_account(accountname, accountemail, accountrole, access_to_billing, scp, root_id, accountbilling):
    """Creates a new child account."""
    account_id = 'None'
    client = get_client('organizations')
    try:
        create_account_response = client.create_account(Email=accountemail, AccountName=accountname,
                                                        RoleName=accountrole,
                                                        IamUserAccessToBilling=access_to_billing,
                                                        Tags=[
                                                            {
                                                                "Key": "AccountBilling",
                                                                "Value": accountbilling
                                                            }
                                                        ])
    except botocore.exceptions.ClientError as exception:
        print(exception)
        sys.exit(1)
    # time.sleep(30)
    create_account_status_response = client.describe_create_account_status(
        CreateAccountRequestId=create_account_response.get('CreateAccountStatus').get('Id'))
    account_id = create_account_status_response.get('CreateAccountStatus').get('AccountId')

    while account_id is None:
        create_account_status_response = client.describe_create_account_status(
            CreateAccountRequestId=create_account_response.get('CreateAccountStatus').get('Id'))
        account_id = create_account_status_response.get('CreateAccountStatus').get('AccountId')
    return (create_account_response, account_id)


def get_template(sourcebucket, baselinetemplate):
    '''
        Read a template file and return the contents
    '''
    print("Reading resources from " + baselinetemplate)

    s3 = boto3.resource('s3')
    # obj = s3.Object('cf-to-create-lambda','5-newbaseline.yml')
    obj = s3.Object(sourcebucket, baselinetemplate)
    return obj.get()['Body'].read().decode('utf-8')


def delete_default_vpc(credentials, currentregion):
    """Deletes default vpc from child account."""
    # print("Default VPC deletion in progress in {}".format(currentregion))

    ec2_client = boto3.client('ec2',
                              aws_access_key_id=credentials['AccessKeyId'],
                              aws_secret_access_key=credentials['SecretAccessKey'],
                              aws_session_token=credentials['SessionToken'],
                              region_name=currentregion)

    vpc_response = ec2_client.describe_vpcs()
    for i in range(0, len(vpc_response['Vpcs'])):
        if (vpc_response['Vpcs'][i]['InstanceTenancy']) == 'default':
            default_vpcid = vpc_response['Vpcs'][0]['VpcId']

    subnet_response = ec2_client.describe_subnets()
    subnet_delete_response = []
    default_subnets = []
    for i in range(0, len(subnet_response['Subnets'])):
        if subnet_response['Subnets'][i]['VpcId'] == default_vpcid:
            default_subnets.append(subnet_response['Subnets'][i]['SubnetId'])
    for i in range(0, len(default_subnets)):
        subnet_delete_response.append(ec2_client.delete_subnet(
            SubnetId=default_subnets[i], DryRun=False)
        )

    # print("Default Subnets" + currentregion + "Deleted.")

    igw_response = ec2_client.describe_internet_gateways()
    for i in range(0, len(igw_response['InternetGateways'])):
        for j in range(0, len(igw_response['InternetGateways'][i]['Attachments'])):
            if igw_response['InternetGateways'][i]['Attachments'][j]['VpcId'] == default_vpcid:
                default_igw = igw_response['InternetGateways'][i]['InternetGatewayId']
    # print(default_igw)
    response = ec2_client.detach_internet_gateway(
            InternetGatewayId=default_igw, VpcId=default_vpcid, DryRun=False
    )
    response = ec2_client.delete_internet_gateway(
                                        InternetGatewayId=default_igw
                                       )

    # print("Default IGW " + currentregion + "Deleted.")

    time.sleep(10)
    delete_vpc_response = ec2_client.delete_vpc(VpcId=default_vpcid, DryRun=False)
    print("Deleted Default VPC in {}".format(currentregion))
    return delete_vpc_response


def deploy_resources(credentials, template, stackname, stackregion,
                     org_id, account_id, configbucket):
    '''
        Create a CloudFormation stack of resources within the new account
    '''

    datestamp = time.strftime("%d/%m/%Y")
    client = boto3.client('cloudformation',
                          aws_access_key_id=credentials['AccessKeyId'],
                          aws_secret_access_key=credentials['SecretAccessKey'],
                          aws_session_token=credentials['SessionToken'],
                          region_name=stackregion)
    print("Creating stack " + stackname + " in " + account_id)
    time.sleep(120)
    creating_stack = True
    while creating_stack is True:
        try:
            creating_stack = False
            create_stack_response = client.create_stack(
                StackName=stackname,
                TemplateBody=template,
                Parameters=[
                    {
                        'ParameterKey': 'OrganizationId',
                        'ParameterValue': org_id
                    }
                ],
                NotificationARNs=[],
                Capabilities=[
                    'CAPABILITY_NAMED_IAM',
                ],
                OnFailure='ROLLBACK',
                Tags=[
                    {
                        'Key': 'ManagedResource',
                        'Value': 'True'
                    },
                    {
                        'Key': 'DeployDate',
                        'Value': datestamp
                    }
                ]
            )
        except botocore.exceptions.ClientError as exception:
            creating_stack = True
            print(exception)
            print("Retrying...")
            time.sleep(10)

    stack_building = True
    time.sleep(120)
    print("Stack creation in process...")
    print(create_stack_response)
    while stack_building is True:
        event_list = client.describe_stack_events(StackName=stackname).get("StackEvents")
        stack_event = event_list[0]

        if (stack_event.get('ResourceType') == 'AWS::CloudFormation::Stack' and
                stack_event.get('ResourceStatus') == 'CREATE_COMPLETE'):
            stack_building = False
            print("Stack construction complete.")
        elif (stack_event.get('ResourceType') == 'AWS::CloudFormation::Stack' and
              stack_event.get('ResourceStatus') == 'ROLLBACK_COMPLETE'):
            stack_building = False
            print("Stack construction failed.")
            sys.exit(1)
        else:
            print(stack_event)
            print("Stack building . . .")
            time.sleep(10)
    stack = client.describe_stacks(StackName=stackname)
    return stack


def assume_role(account_id, account_role):
    """ Assumes role to child account """
    sts_client = boto3.client('sts')
    role_arn = 'arn:aws:iam::' + account_id + ':role/' + account_role
    assuming_role = True
    print("Assuming Role . . .")
    while assuming_role is True:
        try:
            assuming_role = False
            assume_role_object = sts_client.assume_role(
                RoleArn=role_arn,
                RoleSessionName="NewAccountRole"
            )
        except botocore.exceptions.ClientError as exception:
            assuming_role = True
            print(exception)
            print("Retrying...")
            time.sleep(10)

    # From the response that contains the assumed role, get the temporary
    # credentials that can be used to make subsequent API calls
    return assume_role_object['Credentials']


def get_ous(parent_id):
    """ List OUs """
    list_of_ou_ids = []

    ou_client = get_client('organizations')
    paginator = ou_client.get_paginator('list_children')
    iterator  = paginator.paginate(
        ParentId=parent_id,
        ChildType='ORGANIZATIONAL_UNIT')

    for page in iterator:
        for ou_list in page['Children']:
            list_of_ou_ids.append(ou_list['Id'])
            list_of_ou_ids.extend(get_ous(ou_list['Id']))

    return list_of_ou_ids

def get_ou_name_id(event, root_id, organization_unit_name):
    """ Gets OU Name Identifier """
    ou_client = get_client('organizations')
    list_of_ou_ids = []
    list_of_OU_names = []
    ou_name_to_id = {}

    list_of_ou_ids = get_ous(root_id)

    for j in range(len(list_of_ou_ids)):
        response = ou_client.describe_organizational_unit(OrganizationalUnitId=list_of_ou_ids[j])
        OU_name = response['OrganizationalUnit']['Name']
        list_of_OU_names.append(OU_name)

    if organization_unit_name not in list_of_OU_names:
        print(
            "The provided Organization Unit Name doesnt exist. \
              Creating an OU named: {}".format(organization_unit_name))
        try:
            ou_creation_response = ou_client.create_organizational_unit(
                                    ParentId=root_id, Name=organization_unit_name
                                   )
            for k, v in ou_creation_response.items():
                for k1, v1 in v.items():
                    if k1 == 'Name':
                        organization_unit_name = v1
                    if k1 == 'Id':
                        organization_unit_id = v1
        except botocore.exceptions.ClientError as e:
            print("Error in creating the OU: {}".format(e))
            respond_cloudformation(event, "FAILED",
                 {"Message": "Could not list out AWS Organization OUs. Account creation Aborted."})

    else:
        for i in range(len(list_of_OU_names)):
            ou_name_to_id[list_of_OU_names[i]] = list_of_ou_ids[i]
        organization_unit_id = ou_name_to_id[organization_unit_name]

    return (organization_unit_name, organization_unit_id)


def respond_cloudformation(event, status, data=None):
    """ Respond to CloudFormation event """
    responseBody = {
        'Status': status,
        'Reason': 'See the details in CloudWatch Log Stream',
        'PhysicalResourceId': event['ServiceToken'],
        'StackId': event['StackId'],
        'RequestId': event['RequestId'],
        'LogicalResourceId': event['LogicalResourceId'],
        'Data': data
    }

    print('Response = ' + json.dumps(responseBody))
    print(event)
    requests.put(event['ResponseURL'], data=json.dumps(responseBody))


# """
# To run this you use python add_account.py admin_profile
# 0000000000000000000000000000000000000000000000000000000000000000 AlecAccount
# alec-cloudtrail-bucket
#
# To run this are the following input parameters cloudcheckr-admin-api-key
# unique-account-name-in-cloudcheckr cloudtrail-bucket-name billing-bucket-name
#
# The CloudCheckr admin api key is a 64 character string.
# The CloudCheckr Account name is the name of the new account in CloudCheckr.
# The cloudtrail-bucket-name is the name of the s3 bucket with cloudtrail data.
# If this is blank, then no cloudtrail data will be added.
# The billing-bucket-name is the name of the s3 bucket with the DBR.
# For payee accounts this can be left blank.
#
#
# The role used by boto3 must have permissions to create cloudformation stacks
# and IAM Admin actions such as create roles and create policies.
# """

def get_role_arn_from_stack(cloudformation, stackid):
    """
	Uses the stack id to get the role arn from describe_stacks.
	"""

    if stackid is None:
        print("A stack id was not returned. Exiting")
        return None

    cloudformation_stack_description = cloudformation.describe_stacks(StackName=stackid)
    if "Stacks" in cloudformation_stack_description:
        Stacks = cloudformation_stack_description["Stacks"]
        if len(Stacks) > 0:
            if "Outputs" in Stacks[0]:
                Outputs = Stacks[0]["Outputs"]
                if len(Outputs) > 0:

                    if "OutputKey" in Outputs[0]:
                        print("Created a " + Outputs[0]["OutputKey"])
                        print("Created " + Outputs[0]["OutputValue"])
                        if Outputs[0]["OutputKey"] == "RoleArn":
                            print("Found role. Waiting 10 seconds before adding to CloudCheckr.")
                            # AWS makes you wait ten seconds before adding
                            # a role to CloudCheckr sometimes.
                            time.sleep(10)
                            return Outputs[0]["OutputValue"]
                        else:
                            if len(Outputs) > 1:
                                if "OutputKey" in Outputs[1]:
                                    print("Created a " + Outputs[1]["OutputKey"])
                                    print("Created " + Outputs[1]["OutputValue"])
                                    if Outputs[1]["OutputKey"] == "RoleArn":
                                        print("Found role. Waiting 10 seconds \
                                                before adding to CloudCheckr.")
                                        # AWS makes you wait ten seconds before
                                        # adding a role to CloudCheckr sometimes.
                                        time.sleep(10)
                                        return Outputs[1]["OutputValue"]
                                else:
                                    print(
                                        "First and second returned values in the stack \
                                        were neither a role arn. Investigate stack output")
                                    return None
                    else:
                        print("Could not find an output key in the first \
                                cloudformation stack output")
                else:
                    print("The number of Outputs was 0")
            else:
                print(
                    "Could not find Outputs in the first stack values. \
                            Trying again in 10 seconds to let stack complete")
                time.sleep(10)
                return get_role_arn_from_stack(cloudformation, stackid)
        else:
            print("The number of stacks was 0")
    else:
        print("Could not find any stacks in the cloudformation stack description")


def add_role_to_cloudcheckr(env, adminapikey, accountname, rolearn):
    """
	Uses the cross-account role created by the cloud formation stack to add it to CloudCheckr.
	Uses the edit_credential Admin API call.
	"""

    if rolearn is None:
        print("Role Arn from Cloudformation stack was not found, so not \
                credentials were added to CloudCheckr")
        return None

    api_url = env + "/api/account.json/edit_credential"

    edit_credential_info = json.dumps({"use_account": accountname, "aws_role_arn": rolearn})

    response_post = requests.post(api_url, headers={"Content-Type": "application/json",
                         "access_key": adminapikey}, data=edit_credential_info
                      )

    if "Message" in response_post.json():
        print("Successfully added the role " + str(rolearn) + " \
                to the CloudCheckr Account " + accountname)
        print(response_post.json())
        print("CloudChecker Integration Complete for the Account " + accountname)
    else:
        print("FAILED to add the role " + str(rolearn) + " to the \
                CloudCheckr Account " + accountname)
        print(response_post.json())
    return None


def create_iam_role_from_cloud_formation(credentials, external_id, template,
                   stackname, stackregion, billingbucket, cloudtrailbucket, curbucket):
    """ Creates IAM role using information from CloudFormation """
    # session = boto3.Session(profile_name=profile_name)

    cloudformation = boto3.client('cloudformation',
                          aws_access_key_id=credentials['AccessKeyId'],
                          aws_secret_access_key=credentials['SecretAccessKey'],
                          aws_session_token=credentials['SessionToken'],
                          region_name=stackregion)

    # cloudformation = session.client(service_name="cloudformation", region_name="us-east-1")

    cloudformation_output = cloudformation.create_stack(StackName=stackname,
                                                        TemplateURL="https://s3.amazonaws.com/cf-cc-4172017/cc_aws_cfn_iam_stack.template.json",
                                                        Capabilities=["CAPABILITY_IAM"],
                                                        Parameters=[
                                                            {
                                                                "ParameterKey": "ExternalId",
                                                                "ParameterValue": external_id
                                                            },
                                                            {
                                                                "ParameterKey": "BillingBucket",
                                                                "ParameterValue": billingbucket
                                                            },
                                                            {
                                                                "ParameterKey": "CloudTrailBucket",
                                                                "ParameterValue": cloudtrailbucket
                                                            },
                                                            {
                                                                "ParameterKey": "CurBucket",
                                                                "ParameterValue": curbucket
                                                            }
                                                        ])

    print(cloudformation_output)

    stackid = None

    if "StackId" in cloudformation_output:
        stackid = cloudformation_output["StackId"]
    else:
        print("Was not able to create role")
        return None

    # wait thirty seconds to complete the stack creation process
    print("Built in wait of 30 seconds to allow stack to be created")
    time.sleep(30)

    rolearn = get_role_arn_from_stack(cloudformation, stackid)

    return rolearn


def create_account_in_cloudcheckr(env, adminapikey, accountname):
    """
    Creates an account in CloudCheckr that is an empty slate. This will return the external_id
    """

    api_url = env + "/api/account.json/add_account_v3"

    add_account_info = json.dumps({"account_name": accountname})

    response_post = requests.post(api_url, headers={"Content-Type": \
                                  "application/json", "access_key": \
                                  adminapikey}, data=add_account_info)

    if "cc_external_id" in response_post.json():
        print("Successfully created the account " + accountname + \
                " with external_id " + response_post.json()["cc_external_id"])
        print(response_post.json())
        return response_post.json()["cc_external_id"]
    else:
        print(response_post.json())
        return None


def main(event, context):
    """ Main function """
    print(event)
    client = get_client('organizations')
    ec2_client = get_client('ec2')
    accountname = event['ResourceProperties']['AccountName']
    accountemail = event['ResourceProperties']['AccountEmail']
    organization_unit_name = event['ResourceProperties']['OrganizationalUnitName']
    accountrole = 'OrganizationAccountAccessRole'
    stackname = event['ResourceProperties']['StackName']
    stackregion = event['ResourceProperties']['StackRegion']
    sourcebucket = event['ResourceProperties']['SourceBucket']
    baselinetemplate = event['ResourceProperties']['BaselineTemplate']
    accountbilling = event['ResourceProperties']['AccountBilling']
    skip_cloud_checkr = event['ResourceProperties'].get('SkipCloudCheckr', "false")
    configbucket = event['ResourceProperties']['ConfigBucket']

    ## These are cloud checker values.
    apisecret = event['ResourceProperties']['CloudCheckrApiSecret']
    ccstackname = event['ResourceProperties']['CCStackName']
    cloudtrailbucket = event['ResourceProperties']['CloudTrailBucket']
    curbucket = event['ResourceProperties']['CurBucket']
    dbrbucket = event['ResourceProperties']['DbrBucket']
    access_to_billing = "DENY"
    scp = None

    if event['RequestType'] == 'Create':
        sts = boto3.client('sts')
        top_level_account = sts.get_caller_identity().get('Account')
        print("The top level account is " + top_level_account)
        org_client = get_client('organizations')

        try:
            desc_org_response = org_client.describe_organization()
            org_id = desc_org_response['Organization']['Id']
            print("Organization ID" + org_id)
        except:
            org_id = "Error"

        try:
            list_roots_response = org_client.list_roots()
            root_id = list_roots_response['Roots'][0]['Id']
        except:
            root_id = "Error"

        # This means this is being run from a management account.
        if (root_id is not "Error") and (org_id is not "Error"):
            try:
                # Create new account
                print("Creating new account: " + accountname + " (" + accountemail + ")")
                (create_account_response, account_id) = \
                          create_account(accountname, accountemail, accountrole,
                                         access_to_billing, scp, root_id, accountbilling)
                print(create_account_response)
                print("Created account:{}\n".format(account_id))
                time.sleep(20)
            except Exception as exception:
                respond_cloudformation(
                    event, "FAILED",
                    {"Message":f"Failed to create account: {exception}"}
                )
                print("Error creating new account.")
                sys.exit(0)

            # Create resources in the newly vended account
            try:
                # Move account to OU provided
                if organization_unit_name != 'None':
                    try:
                        (organization_unit_name, organization_unit_id) = \
                                get_ou_name_id(event, root_id, organization_unit_name)
                        move_response = org_client.move_account(AccountId=account_id,
                                                                SourceParentId=root_id,
                                                                DestinationParentId=organization_unit_id)
                    except botocore.exceptions.ClientError as exception:
                        # Respond to cloud formation as failure.
                        respond_cloudformation(
                            event, "FAILED",
                            {"Message":f"Failed moving account to OU: {exception}"}
                        )
                        print("An error occured. Org account move response: \
                                {} . Error Stack: {}".format(move_response,
                            exception))
                        sys.exit(0)

                credentials = assume_role(account_id, accountrole)
                template = get_template(sourcebucket, baselinetemplate)

                # deploy cloudformation template (AccountBaseline.yml)
                stack = deploy_resources(credentials, template, stackname,
                                         stackregion, org_id, account_id, configbucket)
                print(stack)
                print("Baseline setup deployment for account " + account_id + \
                        " (" + accountemail + ") complete!")

                # delete default vpc in every region
                regions = []
                regions_response = ec2_client.describe_regions()
                for i in range(0, len(regions_response['Regions'])):
                    regions.append(regions_response['Regions'][i]['RegionName'])
                for r in regions:
                    try:
                        delete_vpc_response = delete_default_vpc(credentials, r)
                    except botocore.exceptions.ClientError as exception:
                        print("An error occured while deleting \
                                Default VPC in {}. Error: {}".format(r, exception))
                        i += 1

                respond_cloudformation(event, "SUCCESS",
                                       {"Message": \
                                          "Account created successfully", \
                                          "AccountID": account_id, \
                                          "LoginURL": "https://" + \
                                          account_id + ".signin.aws.amazon.com/console"})

                # Only run this portion if skip cloud checker flag is set to false
                if skip_cloud_checkr == 'false':
                    env = "https://api.cloudcheckr.com"

                    session = boto3.session.Session()
                    client = session.client(
                        service_name='secretsmanager'
                    )

                    try:
                        get_secret_value_response = client.get_secret_value(
                            SecretId=apisecret
                        )
                    except ClientError as e:
                        respond_cloudformation(
                            event, "FAILED",
                            {"Message":f"Failed to get API key from secrets manager: {e}"}
                        )
                        print("Error fetching API key.")
                        sys.exit(0)
                    else:
                        # Secrets Manager decrypts the secret value using the associated KMS CMK
                        # Depending on whether the secret was a string or binary, only one of
                        # these fields will be populated
                        if 'SecretString' in get_secret_value_response:
                            text_secret_data = get_secret_value_response['SecretString']
                        else:
                            text_secret_data = get_secret_value_response['SecretBinary']

                    secret_json = json.loads(text_secret_data)
                    adminapikey = secret_json['AdminApiKey']

                    external_id = create_account_in_cloudcheckr(env, adminapikey, accountname)

                    if external_id is None:
                        print("Was not able to successfully create an account in CloudCheckr")
                        return

                    rolearn = create_iam_role_from_cloud_formation(credentials, external_id,
                                                                   template, ccstackname,
                                                                   stackregion, dbrbucket,
                                                                   cloudtrailbucket, curbucket)

                    add_role_to_cloudcheckr(env, adminapikey, accountname, rolearn)

            except botocore.exceptions.ClientError as exception:
                print("An error occured. Error Stack: {}".format(exception))
                sys.exit(0)

    if event['RequestType'] == 'Update':
        print("Template in Update Status")
        respond_cloudformation(event, "SUCCESS", {"Message": "Resource update successful!"})
