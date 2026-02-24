---
description: |-
  Use the volocloud provider to interact with the Volo platform.
hide: toc
layout: ""
page_title: "Volocloud Provider"
---

# Volocloud Provider

Use the volocloud provider to interact with the Volo platform.
You MUST configure the provider with the proper credentials before you can use it.

Use the navigation to the left to read about the available resources.

!!! note
    The volocloud provider requires the use of Terraform 1.3.0 or later.

## Example Usage

Terraform 1.3.0 and later:

```terraform
terraform {
  required_providers {
    volocloud = {
      source  = "tf.volo-global.com/volo/volocloud"
      version = "0.0.1"
    }
  }
}

# Configure the volocloud provider
provider "volocloud" {
  account_id                 = "account id obtained during registration"
  api_key                    = "api key obtained during registration"
  api_url                    = "https://api.volocloud.volo.co.nz"
  retain_resources_on_delete = true
}
```

## Provider configuration

The volocloud provider offers two ways to specify the required provider
configuration. The following methods are supported, in this order, and
explained below:

- Static
- Environment variables

### Static

Static configuration can be provided by adding an `account_id` and `api_url`
in-line in the volocloud provider block (can also be provided using
terraform variables):

Usage:

```terraform
provider "volocloud" {
  account_id = "00000000-0000-0000-0000-000000000000"
  api_url    = "https://api.volocloud.volo.co.nz"
}
```

The optional parameter `retain_resources_on_delete` can be used to control if the real resources
that the provider resources create in the target tenant are deleted when the provider runs a DELETE operation
on one of it's resources.

### Environment Variables

You can provide your configuration via the `VOLO_ACCOUNT_ID` and
`VOLO_API_URL`, environment variables, representing your Volo
Account ID and Volo Platform API URL, respectively.

```terraform
provider "volocloud" {}
```

Usage:

```sh
$ export VOLO_ACCOUNT_ID="00000000-0000-0000-0000-000000000000"
$ export VOLO_API_URL="https://api.volocloud.volo.co.nz"
$ terraform plan
```

## Provider Authentication

The volocloud provider offers two ways of providing the API Key for
authentication. The following methods are supported, in this order, and
explained below:

- Static credentials
- Environment variables

### Static Credentials

!!! warning
    Hard-coded credentials are not recommended in any Terraform
    configuration and risks secret leakage should this file ever be committed to a
    public version control system.

Static credentials can be provided by adding an `api_key`
in-line in the volocloud provider block (can also be provided using
terraform variables):

Usage:

```terraform
provider "volocloud" {
  api_key = "random_api_key_obtained_from_the_onboarding_page"
}
```

### Environment Variables

You can provide your credentials via the `VOLO_API_KEY`, environment variables,
representing your Volo Platform API Key.

```terraform
provider "volocloud" {}
```

Usage:

```sh
$ export VOLO_API_KEY="random_api_key_obtained_from_the_onboarding_page"
$ terraform plan
```

## Provider Permissions

The volocloud provider requires certain permissions on the target tenant
to create the provider resources. The required permissions are returned by the account resource
as a configuration attribute and can be used to create these permissions in an automated manner.
The required permissions are different for each CSP.

### AWS Permissions

The account resource creates a cloudformation template and saves it in a customer dedicated S3 bucket.
This cloudformation template MUST be created in the aws tenant management account to create the IAM roles
required for volocloud provider to function. When creating the cloudformation template, the following tags
MUST be associated with the cloudformation template:

| Tag Name    | Tag Value       |
| :---------: | :-------------: |
| Application | VoloLandingZone |
| Owner       | VoloLandingZone |

For integration with Microsoft Entra ID for SSO purposes, the provider needs a service principal (app registration)
with a client secret and the following permissions:

- Microsoft Entra ID Built-in roles:
    - Application Administrator
    - Groups Administrator
- Microsoft Graph API (with consent granted):
    - Type Application: Application.ReadWrite.OwnedBy

### Azure Permissions

Azure requires a service principal (app registration) with a client secret and the following permissions:

- Enterprise Agreement(EA) billing account
    - The service principal, needs permissions to create subscriptions under the EA Enrollment ID, using the SubscriptionCreator role.
      To grant these permissions, MUST use REST APIs and the documentation followed can be found here:
      [Assign Enterprise Agreement roles to service principals - Microsoft Cost Management](https://learn.microsoft.com/en-us/azure/cost-management-billing/manage/assign-roles-azure-service-principals)
- Microsoft Customer Agreement (MCA) billing account
    - The service principal, needs permissions to create subscriptions under the MCA Billing Profile, using the Contributor role.
      To grant access, follow instructions in the Microsoft documentation [here](https://learn.microsoft.com/en-us/azure/cost-management-billing/manage/manage-billing-access)
- Azure Resources:
    - Billing account (MCA/EA) permissions to create subscriptions as described above.
    - Existing subscription, the service principal MUST be configured as owner of the subscription.
    - Microsoft Graph API with consent granted):
        - Application.ReadWrite.All
        - AppRoleAssignment.ReadWrite.All
        - Directory.ReadWrite.All
        - Domain.Read.All
        - Group.ReadWrite.All
        - Policy.Read.All
        - Policy.ReadWrite.ApplicationConfiguration
        - User.ReadWrite.All
    - Microsoft Entra ID Built-in roles.
      If using Microsoft Entra Domain Services, add the service principal to the Built-in roles:
      - Application Administrator
      - Groups Administrator

## Provider Regions

The volocloud provider supports the following regions for each CSP.

### AWS

| Type       | Region Name                     | Location Name  | Location (Physical)  | Abbreviation |
| ---------- | ------------------------------- | -------------- | -------------------- | ------------ |
| aws        | Africa (Cape Town)              | af-south-1     | Cape Town            | afso1        |
| aws        | Asia Pacific (Hong Kong)        | ap-east-1      | Hong Kong            | apea1        |
| aws        | Asia Pacific (Taipei)           | ap-east-2      | Taiwan               | apea2        |
| aws        | Asia Pacific (Tokyo)            | ap-northeast-1 | Tokyo                | apne1        |
| aws        | Asia Pacific (Seoul)            | ap-northeast-2 | Seoul                | apne2        |
| aws        | Asia Pacific (Osaka)            | ap-northeast-3 | Osaka                | apne3        |
| aws        | Asia Pacific (Singapore)        | ap-southeast-1 | Singapore            | apse1        |
| aws        | Asia Pacific (Sydney)           | ap-southeast-2 | Sydney               | apse2        |
| aws        | Asia Pacific (Jakarta)          | ap-southeast-3 | Jakarta              | apse3        |
| aws        | Asia Pacific (Melbourne)        | ap-southeast-4 | Melbourne            | apse4        |
| aws        | Asia Pacific (Malaysia)         | ap-southeast-5 | Malaysia             | apse5        |
| aws        | Asia Pacific (New Zealand)      | ap-southeast-6 | New Zealand          | apse6        |
| aws        | Asia Pacific (Thailand)         | ap-southeast-7 | Thailand             | apse7        |
| aws        | Asia Pacific (Mumbai)           | ap-south-1     | Mumbai               | apso1        |
| aws        | Asia Pacific (Hyderabad)        | ap-south-2     | Hyderabad            | apso2        |
| aws        | Canada (Central)                | ca-central-1   | Montreal             | cace1        |
| aws        | Canada West (Calgary)           | ca-west-1      | Calgary              | cawe1        |
| aws-cn     | Mainland China (Beijing) Region | cn-north-1     | Beijing              | cnno1        |
| aws-cn     | Mainland China (Ningxia) Region | cn-northwest-1 | Ningxia              | cnnw1        |
| aws        | Europe (Frankfurt)              | eu-central-1   | Frankfurt            | euce1        |
| aws        | Europe (Zurich)                 | eu-central-2   | Zurich               | euce2        |
| aws        | Europe (Stockholm)              | eu-north-1     | Stockholm            | euno1        |
| aws        | Europe (Milan)                  | eu-south-1     | Milan                | euso1        |
| aws        | Europe (Spain)                  | eu-south-2     | Spain                | euso2        |
| aws        | Europe (Ireland)                | eu-west-1      | Ireland              | euwe1        |
| aws        | Europe (London)                 | eu-west-2      | London               | euwe2        |
| aws        | Europe (Paris)                  | eu-west-3      | Paris                | euwe3        |
| aws        | Israel (Tel Aviv)               | il-central-1   | Israel               | ilce1        |
| aws        | Middle East (UAE)               | me-central-1   | United Arab Emirates | mece1        |
| aws        | Middle East (Bahrain)           | me-south-1     | Bahrain              | meso1        |
| aws        | Mexico (Central)                | mx-central-1   | Mexico               | mxce1        |
| aws        | South America (São Paulo)       | sa-east-1      | Saõ Paulo            | saea1        |
| aws        | US East (N. Virginia)           | us-east-1      | N. Virginia          | usea1        |
| aws        | US East (Ohio)                  | us-east-2      | Ohio                 | usea2        |
| aws        | US West (N. California)         | us-west-1      | N. California        | uswe1        |
| aws        | US West (Oregon)                | us-west-2      | Oregon               | uswe2        |
| aws-us-gov | AWS GovCloud (US-East)          | us-gov-east-1  | Eastern              | usge1        |
| aws-us-gov | AWS GovCloud (US-West)          | us-gov-west-1  | Northwest            | usgw1        |

### Azure

| Type       | Geography            | Region Name          | Location Name      | Location (Physical) | Abbreviation |
| ---------- | -------------------- | -------------------- | ------------------ | ------------------- | ------------ |
| Public     | Africa               | South Africa North   | southafricanorth   | Johannesburg        | zann         |
| Public     | Africa               | South Africa West    | southafricawest    | Cape Town           | zaww         |
| Public     | Asia Pacific         | East Asia            | eastasia           | Hong Kong           | apee         |
| Public     | Asia Pacific         | Southeast Asia       | southeastasia      | Singapore           | apse         |
| Public     | Australia            | Australia Central    | australiacentral   | Canberra            | aucc         |
| Public     | Australia            | Australia Central 2  | australiacentral2  | Canberra            | auc2         |
| Public     | Australia            | Australia East       | australiaeast      | New South Wales     | auee         |
| Public     | Australia            | Australia Southeast  | australiasoutheast | Victoria            | ause         |
| Public     | Austria              | Austria East         | austriaeast        | Vienna              | atee         |
| Government | Azure Government     | US DoD Central       | usdodcentral       | Iowa                | usdcc        |
| Government | Azure Government     | US DoD East          | usdodeast          | Virginia            | usdee        |
| Government | Azure Government     | US Gov Arizona       | usgovarizona       | Arizona             | usgw3        |
| Government | Azure Government     | US Gov Texas         | usgovtexas         | Texas               | usgcs        |
| Government | Azure Government     | US Gov Virginia      | usgovvirginia      | Virginia            | usgee        |
| Government | Azure Government     | US Sec East          | undisclosed        | Undisclosed         | ussee        |
| Government | Azure Government     | US Sec West          | undisclosed        | Undisclosed         | ussww        |
| Public     | Brazil               | Brazil South         | brazilsouth        | São Paulo State     | brss         |
| Public     | Brazil               | Brazil Southeast     | brazilsoutheast    | Rio de Janeiro      | brse         |
| Public     | Canada               | Canada Central       | canadacentral      | Toronto             | cacc         |
| Public     | Canada               | Canada East          | canadaeast         | Quebec City         | caee         |
| Public     | Chile                | Chile Central        | chilecentral       | Santiago            | clee         |
| China      | China                | China East           | chinaeast          | Shanghai            | cnee         |
| China      | China                | China East 2         | chinaeast2         | Shanghai            | cne2         |
| China      | China                | China North          | chinanorth         | Beijing             | cnnn         |
| China      | China                | China North 2        | chinanorth2        | Beijing             | cnn2         |
| Public     | Europe               | North Europe         | northeurope        | Ireland             | eunn         |
| Public     | Europe               | West Europe          | westeurope         | Netherlands         | euww         |
| Public     | France               | France Central       | francecentral      | Paris               | frcc         |
| Public     | France               | France South         | francesouth        | Marseille           | frss         |
| Public     | Germany              | Germany North        | germanynorth       | Berlin              | denn         |
| Public     | Germany              | Germany West Central | germanywestcentral | Frankfurt           | decw         |
| Public     | India                | Central India        | centralindia       | Pune                | incc         |
| Public     | India                | South India          | southindia         | Chennai             | inss         |
| Public     | India                | West India           | westindia          | Mumbai              | inww         |
| Public     | Indonesia            | Indonesia Central    | indonesiacentral   | Jakarta             | idcc         |
| Public     | Israel               | Israel Central       | israelcentral      | Israel              | ilcc         |
| Public     | Italy                | Italy North          | italynorth         | Milan               | itnn         |
| Public     | Japan                | Japan East           | japaneast          | Tokyo, Saitama      | jpee         |
| Public     | Japan                | Japan West           | japanwest          | Osaka               | jpww         |
| Public     | Korea                | Korea Central        | koreacentral       | Seoul               | krcc         |
| Public     | Korea                | Korea South          | koreasouth         | Busan               | krss         |
| Public     | Malaysia             | Malaysia West        | malaysiawest       | Kuala Lumpur        | myww         |
| Public     | Mexico               | Mexico Central       | mexicocentral      | Querétaro State     | mxcc         |
| Public     | New Zealand          | New Zealand North    | newzealandnorth    | Auckland            | nznn         |
| Public     | Norway               | Norway East          | norwayeast         | Oslo                | noee         |
| Public     | Norway               | Norway West          | norwaywest         | Stavanger           | noww         |
| Public     | Poland               | Poland Central       | polandcentral      | Warsaw              | plcc         |
| Public     | Qatar                | Israel Central       | qatarcentral       | Doha                | qacc         |
| Public     | Spain                | Spain Central        | spaincentral       | Madrid              | escc         |
| Public     | Sweden               | Sweden Central       | swedencentral      | Gävle               | secc         |
| Public     | Switzerland          | Switzerland North    | switzerlandnorth   | Zürich              | chnn         |
| Public     | Switzerland          | Switzerland West     | switzerlandwest    | Geneva              | chww         |
| Public     | United Arab Emirates | UAE Central          | uaecentral         | Abu Dhabi           | aecc         |
| Public     | United Arab Emirates | UAE North            | uaenorth           | Dubai               | aenn         |
| Public     | United Kingdom       | UK South             | uksouth            | London              | gbss         |
| Public     | United Kingdom       | UK West              | ukwest             | Cardiff             | gbww         |
| Public     | United States        | Central US           | centralus          | Iowa                | uscc         |
| Public     | United States        | East US              | eastus             | Virginia            | usee         |
| Public     | United States        | East US 2            | eastus2            | Virginia            | use2         |
| Public     | United States        | North Central US     | northcentralus     | Illinois            | uscn         |
| Public     | United States        | South Central US     | southcentralus     | Texas               | uscs         |
| Public     | United States        | West Central US      | westcentralus      | Wyoming             | uscw         |
| Public     | United States        | West US              | westus             | California          | usww         |
| Public     | United States        | West US 2            | westus2            | Washington          | usw2         |
| Public     | United States        | West US 3            | westus3            | Arizona             | usw3         |

## Customer Tenant Requirements

The customer is responsible for configuring the CSP tenant to allow creation of resource.
Since the Volo volocloud provider creates CSP resources in the customer tenant,
the tenant MUST have valid payment methods associated to allow creation of paid resources.

!!! warning
    Not having a valid payment method will cause the volocloud provider to fail

## Customer Onboarding Pre-Requisites

The procurement method is through the AWS/Azure Marketplace. Volo Cloud Foundations is available here:

  - [AWS Marketplace](https://aws.amazon.com/marketplace/pp/prodview-va4juw6buyd2g?sr=0-1&ref_=beagle&applicationId=AWSMPContessa)
  - [Azure Marketplace](https://azuremarketplace.microsoft.com/en-us/marketplace/apps/vololimited1666556006423.volo-cloud-foundations-saas?tab=Overview)

### Marketplace Registration

The customer will procure the offer from the AWS/Azure Marketplace. The Marketplace will redirect to Volocloud registration page
where the customer must register a new volo account by providing the following information:

  - Volocloud account name
  - Volocloud account email

!!! note "ONLY for AWS Marketplace"
    Provide AWS Management Account ID where Volocloud platform will be deployed.

Once the registration with the Marketplace is successful, the Volocloud registration page will return relevant information
for the customer to use and configure the Volocloud terraform provider. The required information is:

  - Volocloud account id
  - Volocloud API URL
  - Volocloud API Key

### Terraform Client

volocloud provider requires a terraform client environment setup. It can be either open source terraform (or open tofu) cli environment, or
any version of Terraform Cloud/Enterprise (or equivalent tools like Pulumni, Spacelift, etc).

!!! note
    Make sure that the terraform environment doesn't have timeout setting lower than the time needed to deploy volocloud provider
    resources. E.g. Terraform Cloud has a default timeout of 2h.

### Volocloud provider resources

volocloud provider has 3 main types of resources that MUST be created in order of dependencies:

  - The `volocloud_account` resource MUST be created first and its purpose is to create a dedicated space in the Volocloud SaaS platform
    for managing customer related services. Once the account is created it will return AWS Cloudformation Template and/or Azure ARM
    Template which needs to be run (by the customer) to create the role that is required to create the other Volocloud resources. During template creation,
    the following 2 tags MUST be assigned to the template:
      - Application = VoloLandingZone
      - Owner = VoloLandingZone
  - The `volocloud_tenancy_aws` and `volocloud_tenancy_azure` resources MUST be created after the `volocloud_account`
    resource and their purpose is to create the core AWS Accounts/Azure Subscriptions and configure services inside those AWS Accounts/Azure Subscriptions.
  - The `volocloud_tenancy_account` and `volocloud_tenancy_account` resources MUST be created after the
    `volocloud_tenancy_aws` and `volocloud_tenancy_azure` resources, and their purpose is to create a dedicated AWS Account/Azure
    Subscription, per application/per environment to host business workloads. The definition of application is entirely up to the customer and can be as small or
    as big as the customer decides. The documentation for each resource usage is provided to the customer and in marketplace registration page and if required,
    Volo support team is available.

#### Volocloud provider account resource

The account resource requires information provider during marketplace registration process (account name and account email) as well as
the volocloud account id and api key obtained during the marketplace registration process. If the account has an AWS tenancy, will require
the AWS Management Account id and if it has an Azure tenancy, will require the Azure Tenancy ID.

#### Volocloud provider tenancy resources

The AWS tenancy resource, at the very least require the following decisions/input:

  - Tenancy abbreviation
  - Alternate/Primary Contacts
  - Environments aligned to network details
  - Network details if enabled, aligned to environments
  - DNS root domain for the tenancy to be used for private DNS subdomains
  - Assume Role ARN and External ID generated by the account resource
  - Reuse existing AWS Organizations and AWS Identity Cetner or not.
  - Regions for deployment
  - Name of the tenancy resource
  - AWS Accounts root email address. Each account will have a unique +account name to it.

The Azure tenancy resource, at the very least require the following decisions/input:

  - Tenancy abbreviation
  - Billing account information
  - Environments aligned to network details
  - Network details if enabled, aligned to environments
  - DNS root domain for the tenancy to be used for private DNS subdomains
  - Assume Identity generated by the account resource
  - Regions for deployment
  - Name of the tenancy resource
  - AWS Accounts root email address. Each account will have a unique +account name to it.

#### Volocloud provider tenancy_account resources

The AWS tenancy_account resource, at the very least require the following decisions/input:

  - Tenancy abbreviation
  - Environment
  - Network details if enabled
  - Regions for deployment

The Azure tenancy_account resource, at the very least require the following decisions/input:

  - Tenancy abbreviation
  - Billing account information
  - Network details if enabled
  - Regions for deployment

<!-- schema generated by tfplugindocs -->
## Schema

### Optional

- `account_id` (String, Sensitive) This is Volo Account ID. It must be provided, but it can also be sourced from the `VOLO_ACCOUNT_ID` environment variable.
- `api_key` (String, Sensitive) This is Volo API Key. It must be provided, but it can also be sourced from the `VOLO_API_KEY` environment variable.
- `api_url` (String) This is Volo API URL. It must be provided, but it can also be sourced from the `VOLO_API_URL` environment variable.
- `retain_resources_on_delete` (Boolean) This determines if actual resources inside target cloud service provider are being deleted in case volocloud resources are deleted. If not provided, it will use `true`.
