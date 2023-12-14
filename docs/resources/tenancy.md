---
description: |-
  Tenancy resource configuration main schema.
hide: toc
page_title: "volocloud_tenancy Resource"
subcategory: ""
hide:
  - toc
---

# volocloud_tenancy

Tenancy resource configuration main schema.

## Example Usage

### Azure Tenancy

```terraform
# Example using Azure Existing Billing account of type MPA
resource "volocloud_tenancy" "example_azure" {
  csp = "azure"
  csp_configuration = {
    azure = {
      abbreviation = "expl"
      billing = {
        account_type = "mpa"
        existing = {
          connectivity_subscription_id = "00000000-0000-0000-0000-000000000000"
          identity_subscription_id     = "00000000-0000-0000-0000-000000000000"
          management_subscription_id   = "00000000-0000-0000-0000-000000000000"
        }
      }
      budgets = {
        root = [
          {
            amount = 1000
            notifications = [
              {
                contact_emails = [
                  "example@example.com",
                ]
                threshold = 90
              }
            ]
          }
        ]
      }
      dns_domain = "example.com"
      geographies = {
        geo_one = {
          default = true
          regions = {
            primary = {
              address_space = "172.16.0.0/16"
              location      = "australiaeast"
              region        = "auee"
            }
            secondary = {
              address_space = "172.17.0.0/16"
              location      = "australiasoutheast"
              region        = "ause"
            }
          }
        }
      }
      subscriptions = {
        connectivity = {
          abbreviation = "conn"
          azure_bastion = {
            enabled = false
          }
          budgets = [
            {
              amount = 1500
              notifications = [
                {
                  contact_emails = [
                    "example@example.com",
                  ]
                  threshold = 90
                }
              ]
            }
          ]
          ddos_protection_plan = {
            enabled = false
          }
          dns_resolver = {
            inbound = {
              enabled = false
            }
            outbound = {
              enabled = true
              forwarding_domains = [
                {
                  dns_domain = "example.com"
                  dns_servers = [
                    "1.2.3.4",
                    "5.6.7.8",
                  ]
                }
              ]
            }
          }
          dns_zones = {
            private_subdomains = {
              dev  = "dev"
              prod = "prod"
              qa   = "qa"
              test = "test"
            }
            public_domains = [
              "test.example.com",
            ]
          }
          hub_networks = {
            azure_firewall = {
              enabled = true
            }
            enabled = true
            virtual_network_gateway = {
              enabled = true
              s2s_vpns = [
                {
                  gateway_address = "1.2.3.4"
                  gateway_address_space = [
                    "10.10.0.0/16",
                  ]
                  gateway_name = "test"
                }
              ]
              type     = "Vpn"
              vpn_type = "RouteBased"
            }
          }
          keyvault = {
            soft_delete_retention_days = 7
          }
        }
        identity = {
          abbreviation = "id"
          azuread_domain_services = {
            admin_vm = {
              admin_username                       = "local.admin"
              computer_name                        = "aaddsadmin"
              enabled                              = true
              shutdown_schedule_notification_email = "example@example.com"
              shutdown_schedule_recurrence_time    = "0000"
            }
            enabled = true
            notification_recipients = [
              "example@example.com",
            ]
            sku = "Standard"
          }
          budgets = [
            {
              amount = 500
              notifications = [
                {
                  contact_emails = [
                    "example@example.com",
                  ]
                  threshold = 90
                }
              ]
            }
          ]
          keyvault = {
            soft_delete_retention_days = 7
          }
        }
        management = {
          abbreviation = "mgmt"
          automation_account = {
            sku = "Basic"
          }
          budgets = [
            {
              amount = 500
              notifications = [
                {
                  contact_emails = [
                    "example@example.com",
                  ]
                  threshold = 90
                }
              ]
            }
          ]
          keyvault = {
            soft_delete_retention_days = 7
          }
          mdfc = {
            email = "example@example.com"
          }
          vnet = {
            subnets = {
              paas = {
                agw = {
                  enabled = true
                  service_endpoints = [
                    "Microsoft.KeyVault",
                  ]
                }
              }
              standard = {
                secured = {
                  delegation = {
                    actions = [
                      "Microsoft.Network/virtualNetworks/subnets/join/action",
                    ]
                    name    = "psqlfs"
                    service = "Microsoft.DBforPostgreSQL/flexibleServers"

                  }
                  service_endpoints = [
                    "Microsoft.KeyVault",
                    "Microsoft.Storage",
                  ]
                }
              }
            }
            vnet_link_to_private_dns_zones = [
              "privatelink.postgres.database.azure.com",
            ]
          }
        }
      }
      tags = {}
    }
  }
  csp_credentials = {
    azure = {
      azuread = {
        client_id     = "00000000-0000-0000-0000-000000000000"
        client_secret = "client_secret"
        tenant_id     = "00000000-0000-0000-0000-000000000000"
      }
      provider = {
        client_id       = "00000000-0000-0000-0000-000000000000"
        client_secret   = "client_secret"
        subscription_id = "00000000-0000-0000-0000-000000000000"
        tenant_id       = "00000000-0000-0000-0000-000000000000"
      }
    }
  }
  name = "example"
}
```

### AWS Tenancy

```terraform
# Example using Azure Existing Billing account of type MPA
resource "volocloud_tenancy" "aws" {
  configuration = {
    aws = {
      resources = {
        abbreviation = "expl"
        dns_domain   = "example.com"
        email        = "example@example.com"
        geographies = {
          geo_one = {
            default = true
            regions = {
              primary = {
                address_space = "172.16.0.0/16"
                location      = "australiaeast"
                region        = "auee"
              }
            }
          }
        }
        sso = {
          idp = {
            azuread = {}
          }
          sp = {
            acs_url   = ""
            login_url = ""
            sp_url    = ""
          }
        }
        tags = {
          key1 = "value1"
        }
      }
    }
    providers = {
      azuread = {
        client_id     = "00000000-0000-0000-0000-000000000000"
        client_secret = "client_secret"
        tenant_id     = "00000000-0000-0000-0000-000000000000"
      }
      azurerm = {
        client_id       = "00000000-0000-0000-0000-000000000000"
        client_secret   = "client_secret"
        subscription_id = "00000000-0000-0000-0000-000000000000"
        tenant_id       = "00000000-0000-0000-0000-000000000000"
      }
    }
  }
  name = "example"
}
```

<!-- schema generated by tfplugindocs -->
## Schema

### Required

- `csp` (String) (Required) The Cloud Service Provider of the tenancy. Must be one of: `aws`, `azure` or `gcp`.
- `csp_configuration` (Attributes) (Required) Provides configuration required to setup the Tenancy. Only one can be provided at a time. (see [below for nested schema](#nestedatt--csp_configuration))
- `csp_credentials` (Attributes) (Required) Provides required credentials to setup the Tenancy. Only one can be provided at a time. (see [below for nested schema](#nestedatt--csp_credentials))
- `name` (String) (Required) Volocloud tenancy Name.

### Optional

- `trigger_update` (String) (Optional) This attribute provides a mechanism to trigger an update on the tenancy resouce when there is no change to the other attributes.

### Read-Only

- `csp_resources` (Map of String) These are all the resources created in the tenancy.
- `id` (String) (Computed) ID of the resource computed from the account_id and tenancy_id separated by : .
- `last_updated` (String) (Computed) Timestamp when create and/or update run last time.
- `volo_account_id` (String) (Computed) Volocloud Account ID associated with this tenancy.
- `volo_tenancy_id` (String) (Computed) Volocloud Tenancy ID.

<a id="nestedatt--csp_configuration"></a>
### Nested Schema for `csp_configuration`

Optional:

- `aws` (Attributes) (Optional) It contains tenancy resources' configuration. (see [below for nested schema](#nestedatt--csp_configuration--aws))
- `azure` (Attributes) (Optional) It contains tenancy resources' configuration. (see [below for nested schema](#nestedatt--csp_configuration--azure))
- `gcp` (Attributes) (Optional) It contains tenancy resources' configuration. (see [below for nested schema](#nestedatt--csp_configuration--gcp))

<a id="nestedatt--csp_configuration--aws"></a>
### Nested Schema for `csp_configuration.aws`

Required:

- `abbreviation` (String) (Required) This abbreviation will be used to uniquily identify resources created. Only applies to resources that require AWS global uniqueness.
- `accounts` (Attributes) (Required) Configuration details for AWS Accounts part of tenancy. (see [below for nested schema](#nestedatt--csp_configuration--aws--accounts))
- `dns_domain` (String) (Required) DNS domain to be used as the root DNS for the AWS tenancy. private dns subdomains will be created based on this.
- `email` (String) (Required) Email address for the root user of the provisioned AWS Accounts part of this tenancy. Must support subaddressing (+ sign) and be max 42 chars.
- `geographies` (Attributes Map) (Required) Map of nested geography object. (see [below for nested schema](#nestedatt--csp_configuration--aws--geographies))

Optional:

- `sso` (Attributes) (Optional) Configuration details for AWS Identity Centre SSO. (see [below for nested schema](#nestedatt--csp_configuration--aws--sso))
- `tags` (Map of String) (Optional) Key-value map of resource tags for all the tenancy resources.

<a id="nestedatt--csp_configuration--aws--accounts"></a>
### Nested Schema for `csp_configuration.aws.accounts`

Required:

- `audit` (Attributes) (Required) Provides details for configuring audit resources. (see [below for nested schema](#nestedatt--csp_configuration--aws--accounts--audit))
- `log_archive` (Attributes) (Required) Provides details for configuring log archive resources. (see [below for nested schema](#nestedatt--csp_configuration--aws--accounts--log_archive))
- `management` (Attributes) (Required) Provides details for configuring management resources. (see [below for nested schema](#nestedatt--csp_configuration--aws--accounts--management))
- `network` (Attributes) (Required) Provides details for configuring network resources. (see [below for nested schema](#nestedatt--csp_configuration--aws--accounts--network))
- `shared_services` (Attributes) (Required) Provides details for configuring shared services resources. (see [below for nested schema](#nestedatt--csp_configuration--aws--accounts--shared_services))

Optional:

- `password_policy` (Attributes) (Optional) Manages Password Policy for the AWS Account. (see [below for nested schema](#nestedatt--csp_configuration--aws--accounts--password_policy))

<a id="nestedatt--csp_configuration--aws--accounts--audit"></a>
### Nested Schema for `csp_configuration.aws.accounts.password_policy`

Required:

- `securityhub` (Attributes) (Required) Manages the Security Hub Configuration for AWS Organization. (see [below for nested schema](#nestedatt--csp_configuration--aws--accounts--password_policy--securityhub))

Optional:

- `alternate_contacts` (Attributes Map) (Optional) Configuration of AWS Account alternate contacts. (see [below for nested schema](#nestedatt--csp_configuration--aws--accounts--password_policy--alternate_contacts))
- `ebs_encryption_by_default` (Boolean) (Optional) Whether or not default EBS encryption is enabled. Defaults to `true`.
- `guardduty` (Attributes) (Optional) Provides a resource to manage Amazon GuardDuty for this AWS Organization. (see [below for nested schema](#nestedatt--csp_configuration--aws--accounts--password_policy--guardduty))
- `s3_account_public_access_block` (Attributes) (Optional) Manages S3 account-level Public Access Block configuration. (see [below for nested schema](#nestedatt--csp_configuration--aws--accounts--password_policy--s3_account_public_access_block))

<a id="nestedatt--csp_configuration--aws--accounts--password_policy--securityhub"></a>
### Nested Schema for `csp_configuration.aws.accounts.password_policy.securityhub`

Required:

- `enabled` (Boolean) (Required) Enables Security Hub for this AWS Organization and the core AWS Accounts.

Optional:

- `products` (Attributes List) (Optional) Enables the integration of a partner product with Security Hub in Audit AWS Account. Integrated products send/receive findings to/from Security Hub. (see [below for nested schema](#nestedatt--csp_configuration--aws--accounts--password_policy--securityhub--products))
- `standards` (Attributes) (Optional) Manages Security Hub Standards and their controls for this AWS Organization. (see [below for nested schema](#nestedatt--csp_configuration--aws--accounts--password_policy--securityhub--standards))

<a id="nestedatt--csp_configuration--aws--accounts--password_policy--securityhub--products"></a>
### Nested Schema for `csp_configuration.aws.accounts.password_policy.securityhub.standards`

Optional:

- `integration_partner` (String) (Optional) The partner product to integrate with. The format is derived from the product ARN by taking everything after `product/` and replacing `-` and `/` with `_`. Must be one of: `3coresec_3coresec`, `alertlogic_althreatmanagement`, `aqua_security_kube_bench`, `aquasecurity_aquasecurity`, `armordefense_armoranywhere`, `atlassian_jira_service_management`, `atlassian_jira_service_management_cloud`, `atlassian_opsgenie`, `attackiq_attackiq_platform`, `barracuda_cloudsecurityguardian`, `bigid_bigid_enterprise`, `blue_hexagon_blue_hexagon_for_aws`, `capitis_c2vs`, `caveonix_caveonix_cloud`, `checkpoint_cloudguard_iaas`, `checkpoint_dome9_arc`, `claroty_xdome`, `cloud_custodian_cloud_custodian`, `cloud_storage_security_antivirus_for_amazon_s3`, `cloudtamerio_cloudtamerio`, `contrast_security_security_assess`, `crowdstrike_crowdstrike_falcon`, `cyberark_cyberark_pta`, `data_theorem_api_cloud_web_secure`, `disruptops_inc_disruptops`, `fireeye_fireeye_helix`, `forcepoint_forcepoint_casb`, `forcepoint_forcepoint_cloud_security_gateway`, `forcepoint_forcepoint_dlp`, `forcepoint_forcepoint_ngfw`, `fortinet_inc_forticnp_cloud_native_protection`, `fugue_fugue`, `guardicore_aws_infection_monkey`, `guardicore_centra`, `hackerone_vulnerability_intelligence`, `ibm_qradar_siem`, `jfrog_jfrog_xray`, `juniper_networks_vsrx_next_generation_firewall`, `k9_security_access_analyzer`, `lacework_lacework`, `logz_io_cloud_siem`, `mcafee_skyhigh_mcafee_mvision_cloud_aws`, `metricstream_cybergrc`, `micro_focus_arcsight`, `netscout_netscout_cyber_investigator`, `new_relic_vulnerability_management`, `pagerduty_pagerduty`, `paloaltonetworks_demisto`, `paloaltonetworks_paloalto_networks_vmseries`, `paloaltonetworks_redlock`, `prowler_prowler`, `qualys_qualys_vm`, `rackspace_cloud_native_security`, `rapid7_insight_connect`, `rapid7_insightvm`, `rsa_archer`, `secureclouddb_secureclouddb`, `sentinelone_endpoint_protection`, `servicenow_itsm`, `slack_slack`, `snyk_snyk`, `sonrai_security_sonrai_dig`, `sophos_sophos_server_protection`, `splunk_phantom`, `splunk_splunk_enterprise`, `stackrox_kubernetes_security`, `sumologicinc_sumologic_mda`, `symantec_corp_symantec_cwp`, `sysdig_sysdig_secure_for_cloud`, `tenable_tenable_io`, `threatmodeler_software_threatmodeler`, `trend_micro_cloud_one`, `turbot_turbot`, `twistlock_twistlock_enterprise`, `vectra_ai_cognito_detect`, `wiz_security_wiz_security`,
- `integration_region` (String) (Optional) The combination of geography and region keys where the partner product integration should be created. It supports all combinations of geographies and regions as provided in the geographies schema. Defaults to `geo_one_primary`.


<a id="nestedatt--csp_configuration--aws--accounts--password_policy--securityhub--standards"></a>
### Nested Schema for `csp_configuration.aws.accounts.password_policy.securityhub.standards`

Optional:

- `aws_foundational_security_best_practices` (Attributes) (Optional) Manages Security Hub `AWS Foundational Security Best Practices` standard. (see [below for nested schema](#nestedatt--csp_configuration--aws--accounts--password_policy--securityhub--standards--aws_foundational_security_best_practices))
- `cis_aws_foundations_benchmark` (Attributes) (Optional) Manages Security Hub `CIS AWS Foundations Benchmark` standard. (see [below for nested schema](#nestedatt--csp_configuration--aws--accounts--password_policy--securityhub--standards--cis_aws_foundations_benchmark))
- `nist_special_publication_800_53` (Attributes) (Optional) Manages Security Hub `NIST Special Publication 800-53` standard. (see [below for nested schema](#nestedatt--csp_configuration--aws--accounts--password_policy--securityhub--standards--nist_special_publication_800_53))
- `pci_dss` (Attributes) (Optional) Manages Security Hub `PCI DSS` standard. (see [below for nested schema](#nestedatt--csp_configuration--aws--accounts--password_policy--securityhub--standards--pci_dss))

<a id="nestedatt--csp_configuration--aws--accounts--password_policy--securityhub--standards--aws_foundational_security_best_practices"></a>
### Nested Schema for `csp_configuration.aws.accounts.password_policy.securityhub.standards.pci_dss`

Optional:

- `controls` (Attributes Map) (Optional) A map of object to disable control(s) part of this standard. The map keys MUST be the all lowercase control id. (see [below for nested schema](#nestedatt--csp_configuration--aws--accounts--password_policy--securityhub--standards--pci_dss--controls))
- `enabled` (Boolean) (Optional) Enables this Security Hub `Aws Foundational Security Best Practices` standard in the AWS Organization. Defaults to `true`.
- `version` (String) (Optional) Standard `v1.0.0` version.

<a id="nestedatt--csp_configuration--aws--accounts--password_policy--securityhub--standards--pci_dss--controls"></a>
### Nested Schema for `csp_configuration.aws.accounts.password_policy.securityhub.standards.pci_dss.version`

Required:

- `disable_control` (Boolean) (Required) If true, the control will be disabled.
- `disable_reason` (String) (Required) Provides a reason why the control has been disabled.



<a id="nestedatt--csp_configuration--aws--accounts--password_policy--securityhub--standards--cis_aws_foundations_benchmark"></a>
### Nested Schema for `csp_configuration.aws.accounts.password_policy.securityhub.standards.pci_dss`

Optional:

- `controls` (Attributes Map) (Optional) A map of object to disable control(s) part of this standard. The map keys MUST be the all lowercase control id. (see [below for nested schema](#nestedatt--csp_configuration--aws--accounts--password_policy--securityhub--standards--pci_dss--controls))
- `enabled` (Boolean) (Optional) Enables this Security Hub `CIS AWS Foundations Benchmark` standard in the AWS Organization. Defaults to `true`.
- `version` (String) (Optional) Standard `v1.4.0` version.

<a id="nestedatt--csp_configuration--aws--accounts--password_policy--securityhub--standards--pci_dss--controls"></a>
### Nested Schema for `csp_configuration.aws.accounts.password_policy.securityhub.standards.pci_dss.version`

Required:

- `disable_control` (Boolean) (Required) If true, the control will be disabled.
- `disable_reason` (String) (Required) Provides a reason why the control has been disabled.



<a id="nestedatt--csp_configuration--aws--accounts--password_policy--securityhub--standards--nist_special_publication_800_53"></a>
### Nested Schema for `csp_configuration.aws.accounts.password_policy.securityhub.standards.pci_dss`

Required:

- `enabled` (Boolean) (Required) Enables this Security Hub `NIST Special Publication 800-53` standard in the AWS Organization.

Optional:

- `controls` (Attributes Map) (Optional) A map of object to disable control(s) part of this standard. The map keys MUST be the all lowercase control id. (see [below for nested schema](#nestedatt--csp_configuration--aws--accounts--password_policy--securityhub--standards--pci_dss--controls))
- `version` (String) (Optional) Standard `revision_5` version.

<a id="nestedatt--csp_configuration--aws--accounts--password_policy--securityhub--standards--pci_dss--controls"></a>
### Nested Schema for `csp_configuration.aws.accounts.password_policy.securityhub.standards.pci_dss.version`

Required:

- `disable_control` (Boolean) (Required) If true, the control will be disabled.
- `disable_reason` (String) (Required) Provides a reason why the control has been disabled.



<a id="nestedatt--csp_configuration--aws--accounts--password_policy--securityhub--standards--pci_dss"></a>
### Nested Schema for `csp_configuration.aws.accounts.password_policy.securityhub.standards.pci_dss`

Required:

- `enabled` (Boolean) (Required) Enables this Security Hub `PCI DSS` standard in the AWS Organization.

Optional:

- `controls` (Attributes Map) (Optional) A map of object to disable control(s) part of this standard. The map keys MUST be the all lowercase control id. (see [below for nested schema](#nestedatt--csp_configuration--aws--accounts--password_policy--securityhub--standards--pci_dss--controls))
- `version` (String) (Optional) Standard `v3.2.1` version.

<a id="nestedatt--csp_configuration--aws--accounts--password_policy--securityhub--standards--pci_dss--controls"></a>
### Nested Schema for `csp_configuration.aws.accounts.password_policy.securityhub.standards.pci_dss.version`

Required:

- `disable_control` (Boolean) (Required) If true, the control will be disabled.
- `disable_reason` (String) (Required) Provides a reason why the control has been disabled.





<a id="nestedatt--csp_configuration--aws--accounts--password_policy--alternate_contacts"></a>
### Nested Schema for `csp_configuration.aws.accounts.password_policy.alternate_contacts`

Required:

- `email` (String) (Required) An email address for the alternate contact.
- `name` (String) (Required) Name of the alternate contact.
- `phone` (String) (Required) Phone number for the alternate contact.
- `title` (String) (Required) Title for the alternate contact.


<a id="nestedatt--csp_configuration--aws--accounts--password_policy--guardduty"></a>
### Nested Schema for `csp_configuration.aws.accounts.password_policy.guardduty`

Optional:

- `auto_enable_organization_members` (Boolean) (Optional) Indicates the auto-enablement configuration of GuardDuty for the member accounts in the organization. Defaults to true.
- `detector_features` (List of String) (Optional) Provides a resource to manage Amazon GuardDuty organization configuration features. Can be one of: `ebs_malware_protection`, `eks_audit_logs`, `eks_runtime_monitoring`, `eks_runtime_monitoring_addon_management`, `lambda_network_logs`, `rds_login_events`, `s3_data_events`. The `eks_runtime_monitoring_addon_management` is used only if `eks_runtime_monitoring` is present as well.
- `enabled` (Boolean) (Optional) Enables Guardduty for this AWS Organization.
- `finding_publishing_frequency` (String) (Optional) Specifies the frequency of notifications sent for subsequent finding occurrences.Valid values: `FIFTEEN_MINUTES`, `ONE_HOUR`, `SIX_HOURS`.
- `threatiplist` (List of String) (Optional) Provides a resource to manage a GuardDuty ThreatIntelSet.
- `trustiplist` (List of String) (Optional) Provides a resource to manage a GuardDuty IPSet.


<a id="nestedatt--csp_configuration--aws--accounts--password_policy--s3_account_public_access_block"></a>
### Nested Schema for `csp_configuration.aws.accounts.password_policy.s3_account_public_access_block`

Optional:

- `block_public_acls` (Boolean) Optional) Whether Amazon S3 should block public bucket policies for buckets in this account. Defaults to `true`.
- `block_public_policy` (Boolean) (Optional) Whether Amazon S3 should block public bucket policies for buckets in this account. Defaults to `true`.
- `ignore_public_acls` (Boolean) (Optional) Whether Amazon S3 should ignore public ACLs for buckets in this account. Defaults to true.
- `restrict_public_buckets` (Boolean) (Optional) Whether Amazon S3 should restrict public bucket policies for buckets in this account. Defaults to true.



<a id="nestedatt--csp_configuration--aws--accounts--log_archive"></a>
### Nested Schema for `csp_configuration.aws.accounts.password_policy`

Optional:

- `alternate_contacts` (Attributes Map) (Optional) Configuration of AWS Account alternate contacts. (see [below for nested schema](#nestedatt--csp_configuration--aws--accounts--password_policy--alternate_contacts))
- `ebs_encryption_by_default` (Boolean) (Optional) Whether or not default EBS encryption is enabled. Defaults to `true`.
- `s3_account_public_access_block` (Attributes) (Optional) Manages S3 account-level Public Access Block configuration. (see [below for nested schema](#nestedatt--csp_configuration--aws--accounts--password_policy--s3_account_public_access_block))

<a id="nestedatt--csp_configuration--aws--accounts--password_policy--alternate_contacts"></a>
### Nested Schema for `csp_configuration.aws.accounts.password_policy.alternate_contacts`

Required:

- `email` (String) (Required) An email address for the alternate contact.
- `name` (String) (Required) Name of the alternate contact.
- `phone` (String) (Required) Phone number for the alternate contact.
- `title` (String) (Required) Title for the alternate contact.


<a id="nestedatt--csp_configuration--aws--accounts--password_policy--s3_account_public_access_block"></a>
### Nested Schema for `csp_configuration.aws.accounts.password_policy.s3_account_public_access_block`

Optional:

- `block_public_acls` (Boolean) Optional) Whether Amazon S3 should block public bucket policies for buckets in this account. Defaults to `true`.
- `block_public_policy` (Boolean) (Optional) Whether Amazon S3 should block public bucket policies for buckets in this account. Defaults to `true`.
- `ignore_public_acls` (Boolean) (Optional) Whether Amazon S3 should ignore public ACLs for buckets in this account. Defaults to true.
- `restrict_public_buckets` (Boolean) (Optional) Whether Amazon S3 should restrict public bucket policies for buckets in this account. Defaults to true.



<a id="nestedatt--csp_configuration--aws--accounts--management"></a>
### Nested Schema for `csp_configuration.aws.accounts.password_policy`

Optional:

- `alternate_contacts` (Attributes Map) (Optional) Configuration of AWS Account alternate contacts. (see [below for nested schema](#nestedatt--csp_configuration--aws--accounts--password_policy--alternate_contacts))
- `ebs_encryption_by_default` (Boolean) (Optional) Whether or not default EBS encryption is enabled. Defaults to `true`.
- `s3_account_public_access_block` (Attributes) (Optional) Manages S3 account-level Public Access Block configuration. (see [below for nested schema](#nestedatt--csp_configuration--aws--accounts--password_policy--s3_account_public_access_block))

<a id="nestedatt--csp_configuration--aws--accounts--password_policy--alternate_contacts"></a>
### Nested Schema for `csp_configuration.aws.accounts.password_policy.alternate_contacts`

Required:

- `email` (String) (Required) An email address for the alternate contact.
- `name` (String) (Required) Name of the alternate contact.
- `phone` (String) (Required) Phone number for the alternate contact.
- `title` (String) (Required) Title for the alternate contact.


<a id="nestedatt--csp_configuration--aws--accounts--password_policy--s3_account_public_access_block"></a>
### Nested Schema for `csp_configuration.aws.accounts.password_policy.s3_account_public_access_block`

Optional:

- `block_public_acls` (Boolean) Optional) Whether Amazon S3 should block public bucket policies for buckets in this account. Defaults to `true`.
- `block_public_policy` (Boolean) (Optional) Whether Amazon S3 should block public bucket policies for buckets in this account. Defaults to `true`.
- `ignore_public_acls` (Boolean) (Optional) Whether Amazon S3 should ignore public ACLs for buckets in this account. Defaults to true.
- `restrict_public_buckets` (Boolean) (Optional) Whether Amazon S3 should restrict public bucket policies for buckets in this account. Defaults to true.



<a id="nestedatt--csp_configuration--aws--accounts--network"></a>
### Nested Schema for `csp_configuration.aws.accounts.password_policy`

Required:

- `aws_account_close_on_delete` (Boolean) (Required) If `true`, this will close the AWS account on resource deletion, beginning the 90-day suspension period. Otherwise, the account will just be unenrolled from Control Tower.

Optional:

- `alternate_contacts` (Attributes Map) (Optional) Configuration of AWS Account alternate contacts. (see [below for nested schema](#nestedatt--csp_configuration--aws--accounts--password_policy--alternate_contacts))
- `cloud_wan` (Attributes) (Optional) Cloud WAN architecture. Conflicts with `transit_gateway`. (see [below for nested schema](#nestedatt--csp_configuration--aws--accounts--password_policy--cloud_wan))
- `deployment_architectures` (Attributes) (Optional) Deployment architectures for the network account VPC(s). (see [below for nested schema](#nestedatt--csp_configuration--aws--accounts--password_policy--deployment_architectures))
- `dns_resolver` (Attributes) (Optional) AWS Private DNS Resolver configuration. (see [below for nested schema](#nestedatt--csp_configuration--aws--accounts--password_policy--dns_resolver))
- `dns_zones` (Attributes) (Optional) AWS DNS Zones for public and private DNS object. (see [below for nested schema](#nestedatt--csp_configuration--aws--accounts--password_policy--dns_zones))
- `ebs_encryption_by_default` (Boolean) (Optional) Whether or not default EBS encryption is enabled. Defaults to true.
- `network_firewall` (Attributes) (Optional) Provides details for configuring AWS Network Firewall service. (see [below for nested schema](#nestedatt--csp_configuration--aws--accounts--password_policy--network_firewall))
- `s3_account_public_access_block` (Attributes) (Optional) Manages S3 account-level Public Access Block configuration. (see [below for nested schema](#nestedatt--csp_configuration--aws--accounts--password_policy--s3_account_public_access_block))
- `transit_gateway` (Attributes) (Optional) Hub and Spoke architecture. Conflicts with `cloud_wan`. (see [below for nested schema](#nestedatt--csp_configuration--aws--accounts--password_policy--transit_gateway))

<a id="nestedatt--csp_configuration--aws--accounts--password_policy--alternate_contacts"></a>
### Nested Schema for `csp_configuration.aws.accounts.password_policy.alternate_contacts`

Required:

- `email` (String) (Required) An email address for the alternate contact.
- `name` (String) (Required) Name of the alternate contact.
- `phone` (String) (Required) Phone number for the alternate contact.
- `title` (String) (Required) Title for the alternate contact.


<a id="nestedatt--csp_configuration--aws--accounts--password_policy--cloud_wan"></a>
### Nested Schema for `csp_configuration.aws.accounts.password_policy.cloud_wan`

Required:

- `enabled` (Boolean) (Required) If true, deploys a Cloud WAN architecture.


<a id="nestedatt--csp_configuration--aws--accounts--password_policy--deployment_architectures"></a>
### Nested Schema for `csp_configuration.aws.accounts.password_policy.deployment_architectures`

Optional:

- `centralized_egress` (Attributes) (Optional) Configuration for deploying a centralized egress architecture. (see [below for nested schema](#nestedatt--csp_configuration--aws--accounts--password_policy--deployment_architectures--centralized_egress))

<a id="nestedatt--csp_configuration--aws--accounts--password_policy--deployment_architectures--centralized_egress"></a>
### Nested Schema for `csp_configuration.aws.accounts.password_policy.deployment_architectures.centralized_egress`

Optional:

- `availability_zones` (List of String) (Optional) How many AZs to use for central egress VPC? The list MUST contain either 2 or 3 elements. It can be combination of any 2 items or all items from list: `[1, 2, 3]`. Defaults to `[1, 2]`.

Read-Only:

- `enabled` (Boolean) (Computed) Deploy centralized egress architecture. Cannot be disabled.



<a id="nestedatt--csp_configuration--aws--accounts--password_policy--dns_resolver"></a>
### Nested Schema for `csp_configuration.aws.accounts.password_policy.dns_resolver`

Optional:

- `enabled` (Boolean) (Optional) Is AWS Private Resolver DNS enabled?
- `forwarding_domains` (Attributes List) (Optional) Provides a list of objects to configure outbound conditional forwarding. (see [below for nested schema](#nestedatt--csp_configuration--aws--accounts--password_policy--dns_resolver--forwarding_domains))

<a id="nestedatt--csp_configuration--aws--accounts--password_policy--dns_resolver--forwarding_domains"></a>
### Nested Schema for `csp_configuration.aws.accounts.password_policy.dns_resolver.forwarding_domains`

Required:

- `dns_domain` (String) (Required) DNS domain for conditional forwarding.
- `dns_servers` (List of String) (Required) List of DNS servers that are authoritative for the domain.



<a id="nestedatt--csp_configuration--aws--accounts--password_policy--dns_zones"></a>
### Nested Schema for `csp_configuration.aws.accounts.password_policy.dns_zones`

Optional:

- `private_subdomains` (Attributes) (Optional) Object contains the private DNS domain for each environment. (see [below for nested schema](#nestedatt--csp_configuration--aws--accounts--password_policy--dns_zones--private_subdomains))
- `public_domains` (List of String) (Optional) List contains the public DNS domains.

<a id="nestedatt--csp_configuration--aws--accounts--password_policy--dns_zones--private_subdomains"></a>
### Nested Schema for `csp_configuration.aws.accounts.password_policy.dns_zones.public_domains`

Optional:

- `dev` (String) (Optional) The subdomain name for creating the DEV environment private dns zone.
- `prod` (String) (Optional) The subdomain name for creating the PROD environment private dns zone.
- `qa` (String) (Optional) The subdomain name for creating the QA environment private dns zone.
- `test` (String) (Optional) The subdomain name for creating the TEST environment private dns zone.



<a id="nestedatt--csp_configuration--aws--accounts--password_policy--network_firewall"></a>
### Nested Schema for `csp_configuration.aws.accounts.password_policy.network_firewall`

Optional:

- `enabled` (Boolean) (Optional) Is Network Firewall enabled? Defaults to `true`.
- `type` (String) (Optional) The type of Network Firewall to deploy. Can be one of: `aws` to deploy (by this resource) AWS Network Firewall or `partner` to deploy (separately) a 3rd party firewall using GWLB. Defaults to `aws`


<a id="nestedatt--csp_configuration--aws--accounts--password_policy--s3_account_public_access_block"></a>
### Nested Schema for `csp_configuration.aws.accounts.password_policy.s3_account_public_access_block`

Optional:

- `block_public_acls` (Boolean) Optional) Whether Amazon S3 should block public bucket policies for buckets in this account. Defaults to `true`.
- `block_public_policy` (Boolean) (Optional) Whether Amazon S3 should block public bucket policies for buckets in this account. Defaults to `true`.
- `ignore_public_acls` (Boolean) (Optional) Whether Amazon S3 should ignore public ACLs for buckets in this account. Defaults to true.
- `restrict_public_buckets` (Boolean) (Optional) Whether Amazon S3 should restrict public bucket policies for buckets in this account. Defaults to true.


<a id="nestedatt--csp_configuration--aws--accounts--password_policy--transit_gateway"></a>
### Nested Schema for `csp_configuration.aws.accounts.password_policy.transit_gateway`

Required:

- `enabled` (Boolean) (Required) If true, deploys a Hub and Spoke architecture based on AWS Transit Gateway.

Optional:

- `aws_side_asn` (Number) (Optional) Private Autonomous System Number (ASN) for the Amazon side of a BGP session. The range is `64512` to `65534` for 16-bit ASNs and `4200000000` to `4294967294` for 32-bit ASNs. Extra AWS Regions will increment by 1. Defaults to `65000`.
- `vpc` (Attributes) (Optional) Configuration for the VPC deployed in the Hub. (see [below for nested schema](#nestedatt--csp_configuration--aws--accounts--password_policy--transit_gateway--vpc))

<a id="nestedatt--csp_configuration--aws--accounts--password_policy--transit_gateway--vpc"></a>
### Nested Schema for `csp_configuration.aws.accounts.password_policy.transit_gateway.vpc`

Optional:

- `enable_dns_hostnames` (Boolean) (Optional) A boolean flag to enable/disable DNS hostnames in the VPC. Defaults to `true`.
- `enable_dns_support` (Boolean) (Optional) A boolean flag to enable/disable DNS support in the VPC. Defaults to `true`.
- `instance_tenancy` (String) (Optional) A tenancy option for instances launched into the VPC. Default is `default`, which ensures that EC2 instances launched in this VPC use the EC2 instance tenancy attribute specified when the EC2 instance is launched. The only other option is `dedicated`, which ensures that EC2 instances launched in this VPC are run on dedicated tenancy instances regardless of the tenancy attribute specified at launch.




<a id="nestedatt--csp_configuration--aws--accounts--shared_services"></a>
### Nested Schema for `csp_configuration.aws.accounts.password_policy`

Required:

- `aws_account_close_on_delete` (Boolean) (Required) If `true`, this will close the AWS account on resource deletion, beginning the 90-day suspension period. Otherwise, the account will just be unenrolled from Control Tower.

Optional:

- `alternate_contacts` (Attributes Map) (Optional) Configuration of AWS Account alternate contacts. (see [below for nested schema](#nestedatt--csp_configuration--aws--accounts--password_policy--alternate_contacts))
- `ebs_encryption_by_default` (Boolean) (Optional) Whether or not default EBS encryption is enabled. Defaults to `true`.
- `s3_account_public_access_block` (Attributes) (Optional) Manages S3 account-level Public Access Block configuration. (see [below for nested schema](#nestedatt--csp_configuration--aws--accounts--password_policy--s3_account_public_access_block))

<a id="nestedatt--csp_configuration--aws--accounts--password_policy--alternate_contacts"></a>
### Nested Schema for `csp_configuration.aws.accounts.password_policy.alternate_contacts`

Required:

- `email` (String) (Required) An email address for the alternate contact.
- `name` (String) (Required) Name of the alternate contact.
- `phone` (String) (Required) Phone number for the alternate contact.
- `title` (String) (Required) Title for the alternate contact.


<a id="nestedatt--csp_configuration--aws--accounts--password_policy--s3_account_public_access_block"></a>
### Nested Schema for `csp_configuration.aws.accounts.password_policy.s3_account_public_access_block`

Optional:

- `block_public_acls` (Boolean) Optional) Whether Amazon S3 should block public bucket policies for buckets in this account. Defaults to `true`.
- `block_public_policy` (Boolean) (Optional) Whether Amazon S3 should block public bucket policies for buckets in this account. Defaults to `true`.
- `ignore_public_acls` (Boolean) (Optional) Whether Amazon S3 should ignore public ACLs for buckets in this account. Defaults to true.
- `restrict_public_buckets` (Boolean) (Optional) Whether Amazon S3 should restrict public bucket policies for buckets in this account. Defaults to true.



<a id="nestedatt--csp_configuration--aws--accounts--password_policy"></a>
### Nested Schema for `csp_configuration.aws.accounts.password_policy`

Optional:

- `allow_users_to_change_password` (Boolean) (Optional) Whether to allow users to change their own password. Defaults to true.
- `hard_expiry` (Boolean) (Optional) Whether users are prevented from setting a new password after their password has expired (i.e., require administrator reset). Defaults to false.
- `max_password_age` (Number) (Optional) The number of days that an user password is valid. Defaults to 90.
- `minimum_password_length` (Number) (Optional) Minimum length to require for user passwords. Defaults to 14.
- `password_reuse_prevention` (Number) (Optional) The number of previous passwords that users are prevented from reusing. Defaults to 24.
- `require_lowercase_characters` (Boolean) (Optional) Whether to require lowercase characters for user passwords.. Defaults to true.
- `require_numbers` (Boolean) (Optional) Whether to require numbers for user passwords. Defaults to true.
- `require_symbols` (Boolean) (Optional) Whether to require symbols for user passwords. Defaults to true.
- `require_uppercase_characters` (Boolean) (Optional) Whether to require uppercase characters for user passwords. Defaults to true.



<a id="nestedatt--csp_configuration--aws--geographies"></a>
### Nested Schema for `csp_configuration.aws.geographies`

Required:

- `default` (Boolean) (Required) Marks the default geography. Only one can be true.
- `regions` (Attributes) (Required) Object containing 2 Aws Regions in the same geography. Must provide at least 1 primary region. (see [below for nested schema](#nestedatt--csp_configuration--aws--geographies--regions))

<a id="nestedatt--csp_configuration--aws--geographies--regions"></a>
### Nested Schema for `csp_configuration.aws.geographies.regions`

Required:

- `primary` (Attributes) (Required) Primary Aws Region details. (see [below for nested schema](#nestedatt--csp_configuration--aws--geographies--regions--primary))

Optional:

- `secondary` (Attributes) (Optional) Secondary Aws Region details. (see [below for nested schema](#nestedatt--csp_configuration--aws--geographies--regions--secondary))

<a id="nestedatt--csp_configuration--aws--geographies--regions--primary"></a>
### Nested Schema for `csp_configuration.aws.geographies.regions.primary`

Required:

- `address_space` (String) (Required) The base IP CIDR for the entire region. This will be automatically managed and split into multiple ranges for VPCs and Subnets.
- `location` (String) (Required) The Aws location of the region. Must be one of the Aws supported locations.
- `region` (String) (Required) The Aws region code of the location. Must be one of the region codes associated with Aws supported locations.


<a id="nestedatt--csp_configuration--aws--geographies--regions--secondary"></a>
### Nested Schema for `csp_configuration.aws.geographies.regions.secondary`

Required:

- `address_space` (String) (Required) The base IP CIDR for the entire region. This will be automatically managed and split into multiple ranges for VPCs and Subnets.
- `location` (String) (Required) The Aws location of the region. Must be one of the Aws supported locations.
- `region` (String) (Required) The Aws region code of the location. Must be one of the region codes associated with Aws supported locations.




<a id="nestedatt--csp_configuration--aws--sso"></a>
### Nested Schema for `csp_configuration.aws.sso`

Required:

- `idp` (Attributes) (Required) IdP details for AWS Identity Centre SSO. (see [below for nested schema](#nestedatt--csp_configuration--aws--sso--idp))
- `sp` (Attributes) (Required) Service Provider details for AWS Identity Centre SSO. (see [below for nested schema](#nestedatt--csp_configuration--aws--sso--sp))

<a id="nestedatt--csp_configuration--aws--sso--idp"></a>
### Nested Schema for `csp_configuration.aws.sso.sp`

Required:

- `type` (String) (Required) Provide the IdP type. Supported values are: azuread.

Optional:

- `azuread` (Attributes) (Optional) Details required to setup AzureAD as IdP. (see [below for nested schema](#nestedatt--csp_configuration--aws--sso--sp--azuread))

<a id="nestedatt--csp_configuration--aws--sso--sp--azuread"></a>
### Nested Schema for `csp_configuration.aws.sso.sp.azuread`

Optional:

- `notification_email_addresses` (List of String) (Optional) Provides a list of emails to receive notifications from the service principal associated with the AWS Single-Sign-On Enterprise Application.
- `owners` (List of String) (Optional) Provides a list of AzureAD UPNs that would be configured as owners of the AWS Single-Sign-On Enterprise Application.



<a id="nestedatt--csp_configuration--aws--sso--sp"></a>
### Nested Schema for `csp_configuration.aws.sso.sp`

Required:

- `acs_url` (String) (Required) AWS Identity Centre Assertion Consumer Service URL.
- `login_url` (String) (Required) AWS Identity Centre Access Portal Login URL.
- `sp_url` (String) (Required) AWS Identity Centre Service Provider URL.




<a id="nestedatt--csp_configuration--azure"></a>
### Nested Schema for `csp_configuration.azure`

Required:

- `abbreviation` (String) (Required) This abbreviation will be used to uniquily identify resources created. Only applies to resources that require Azure global uniqueness and to Management Groups.
- `billing` (Attributes) (Required) Provides the details required for Microsoft Azure billing. Must provide only one of ea, existing, mca, mpa attributes. (see [below for nested schema](#nestedatt--csp_configuration--azure--billing))
- `dns_domain` (String) (Required) DNS domain associated with this tenancy.
- `geographies` (Attributes Map) (Required) Map of nested geography object. (see [below for nested schema](#nestedatt--csp_configuration--azure--geographies))
- `subscriptions` (Attributes) (Required) Azure Core Subscriptions: connectivity, identity and management configuration. (see [below for nested schema](#nestedatt--csp_configuration--azure--subscriptions))

Optional:

- `budgets` (Attributes) (Optional) Provides a nested List of nested budget object to associate with a Management Group. (see [below for nested schema](#nestedatt--csp_configuration--azure--budgets))
- `tags` (Map of String) (Optional) Key-value map of resource tags for all the tenancy resources.

<a id="nestedatt--csp_configuration--azure--billing"></a>
### Nested Schema for `csp_configuration.azure.billing`

Required:

- `account_type` (String) (Required) Microsoft Azure Billing Account type. Must be one of ea, mca, mpa.

Optional:

- `ea` (Attributes) (Optional) Provides required billing information to create subscriptions for a Microsoft Enterprise Agreement billing account. Conflicts with existing, mca, mpa. (see [below for nested schema](#nestedatt--csp_configuration--azure--billing--ea))
- `existing` (Attributes) (Optional) Provides existing tenancy core subscription ids. Conflicts with ea, mca, mpa. (see [below for nested schema](#nestedatt--csp_configuration--azure--billing--existing))
- `mca` (Attributes) (Optional) Provides required billing information to create subscriptions for an Microsoft Customer Agreement billing account. Conflicts with existing, ea, mpa. (see [below for nested schema](#nestedatt--csp_configuration--azure--billing--mca))
- `mpa` (Attributes) (Optional) All the CSP Partners that we support to create subscriptions programatically. Conflicts with ea, existing, mca attributes. (see [below for nested schema](#nestedatt--csp_configuration--azure--billing--mpa))

<a id="nestedatt--csp_configuration--azure--billing--ea"></a>
### Nested Schema for `csp_configuration.azure.billing.mpa`

Required:

- `account_id` (String) (Required) Microsoft Enterprise Agreement billing account id.
- `enrollment_id` (String) (Required) Microsoft Enterprise Agreement billing enrollment id.


<a id="nestedatt--csp_configuration--azure--billing--existing"></a>
### Nested Schema for `csp_configuration.azure.billing.mpa`

Required:

- `connectivity_subscription_id` (String) (Required) Existing subscription id to be used for connectivity.
- `identity_subscription_id` (String) (Required) Existing subscription id to be used for identity.
- `management_subscription_id` (String) (Required) Existing subscription id to be used for management.


<a id="nestedatt--csp_configuration--azure--billing--mca"></a>
### Nested Schema for `csp_configuration.azure.billing.mpa`

Required:

- `account_id` (String) (Required) Microsoft Customer Agreement billing account id.
- `invoice_id` (String) (Required) Microsoft Customer Agreement billing invoice id.
- `profile_id` (String) (Required) Microsoft Customer Agreement billing profile id.


<a id="nestedatt--csp_configuration--azure--billing--mpa"></a>
### Nested Schema for `csp_configuration.azure.billing.mpa`

Optional:

- `rhipe` (Attributes) (see [below for nested schema](#nestedatt--csp_configuration--azure--billing--mpa--rhipe))

<a id="nestedatt--csp_configuration--azure--billing--mpa--rhipe"></a>
### Nested Schema for `csp_configuration.azure.billing.mpa.rhipe`

Optional:

- `description` (String) (Optional) Rhipe Description.




<a id="nestedatt--csp_configuration--azure--geographies"></a>
### Nested Schema for `csp_configuration.azure.geographies`

Required:

- `default` (Boolean) (Required) Marks the default geography. Only one can be true.
- `regions` (Attributes) (Required) Object containing the 2 Azure Paired Regions if applicable. Must provide at least 1 primary region. (see [below for nested schema](#nestedatt--csp_configuration--azure--geographies--regions))

<a id="nestedatt--csp_configuration--azure--geographies--regions"></a>
### Nested Schema for `csp_configuration.azure.geographies.regions`

Required:

- `primary` (Attributes) (Required) Primary Azure Region details. (see [below for nested schema](#nestedatt--csp_configuration--azure--geographies--regions--primary))

Optional:

- `secondary` (Attributes) (Optional) Secondary, paired, Azure Region details. (see [below for nested schema](#nestedatt--csp_configuration--azure--geographies--regions--secondary))

<a id="nestedatt--csp_configuration--azure--geographies--regions--primary"></a>
### Nested Schema for `csp_configuration.azure.geographies.regions.primary`

Required:

- `address_space` (String) (Required) The base IP CIDR for the entire region. This will be automatically managed and split into multiple ranges for VNETs and Subnets.
- `location` (String) (Required) The Azure location of the region. Must be one of the Azure supported locations.
- `region` (String) (Required) The Azure region code of the location. Must be one of the region codes associated with Azure supported locations.


<a id="nestedatt--csp_configuration--azure--geographies--regions--secondary"></a>
### Nested Schema for `csp_configuration.azure.geographies.regions.secondary`

Required:

- `address_space` (String) (Required) The base IP CIDR for the entire region. This will be automatically managed and split into multiple ranges for VNETs and Subnets.
- `location` (String) (Required) The Azure location of the region. Must be one of the Azure supported locations.
- `region` (String) (Required) The Azure region code of the location. Must be one of the region codes associated with Azure supported locations.




<a id="nestedatt--csp_configuration--azure--subscriptions"></a>
### Nested Schema for `csp_configuration.azure.subscriptions`

Required:

- `connectivity` (Attributes) (Required) Provides details for configuring connectivity resources. (see [below for nested schema](#nestedatt--csp_configuration--azure--subscriptions--connectivity))
- `identity` (Attributes) (Required) Provides details for configuring identity resources. (see [below for nested schema](#nestedatt--csp_configuration--azure--subscriptions--identity))
- `management` (Attributes) (Required) Provides details for configuring management resources. (see [below for nested schema](#nestedatt--csp_configuration--azure--subscriptions--management))

<a id="nestedatt--csp_configuration--azure--subscriptions--connectivity"></a>
### Nested Schema for `csp_configuration.azure.subscriptions.management`

Required:

- `abbreviation` (String) (Required) This abbreviation will be used to uniquily identify resources created in this subscription. Only applies to resources that require Azure global uniqueness.

Optional:

- `azure_bastion` (Attributes) (Optional) Azure Bastion configuration details. (see [below for nested schema](#nestedatt--csp_configuration--azure--subscriptions--management--azure_bastion))
- `budgets` (Attributes List) (Optional) Provides a list of budget objects. (see [below for nested schema](#nestedatt--csp_configuration--azure--subscriptions--management--budgets))
- `ddos_protection_plan` (Attributes) (Optional) Azure DDOS Protection Plan configuration. If not provides, DDOS Protection Plan will not be enabled. (see [below for nested schema](#nestedatt--csp_configuration--azure--subscriptions--management--ddos_protection_plan))
- `dns_resolver` (Attributes) (Optional) Azure Private DNS Resolver configuration. (see [below for nested schema](#nestedatt--csp_configuration--azure--subscriptions--management--dns_resolver))
- `dns_zones` (Attributes) (Optional) Azure DNS Zones for public and private DNS object. (see [below for nested schema](#nestedatt--csp_configuration--azure--subscriptions--management--dns_zones))
- `hub_networks` (Attributes) (Optional) Hub and Spoke setup. Conflicts with vwan_hub_networks. (see [below for nested schema](#nestedatt--csp_configuration--azure--subscriptions--management--hub_networks))
- `keyvault` (Attributes) (Optional) Azure KeyVault configuration details. (see [below for nested schema](#nestedatt--csp_configuration--azure--subscriptions--management--keyvault))
- `resource_groups_lock` (Attributes) (Optional) Configures Azure Delete Lock at Resource Groups level. (see [below for nested schema](#nestedatt--csp_configuration--azure--subscriptions--management--resource_groups_lock))
- `vwan_hub_networks` (Attributes) (Optional) VWAN setup. Conflicts with hub_networks. (see [below for nested schema](#nestedatt--csp_configuration--azure--subscriptions--management--vwan_hub_networks))

<a id="nestedatt--csp_configuration--azure--subscriptions--management--azure_bastion"></a>
### Nested Schema for `csp_configuration.azure.subscriptions.management.azure_bastion`

Optional:

- `copy_paste` (Boolean) (Optional) Is Copy/Paste feature enabled for the Bastion Host. Defaults to true.
- `enabled` (Boolean) (Optional) Is Azure Bastion enabled? Defaults to true.
- `file_copy` (Boolean) (Optional) Is File Copy feature enabled for the Bastion Host. Defaults to false.
- `sku` (String) (Optional) The SKU of the Bastion Host. Accepted values are Basic and Standard. Defaults to Basic.
- `tunneling` (Boolean) (Optional) Is Tunneling feature enabled for the Bastion Host. Defaults to false.


<a id="nestedatt--csp_configuration--azure--subscriptions--management--budgets"></a>
### Nested Schema for `csp_configuration.azure.subscriptions.management.budgets`

Required:

- `amount` (Number) (Required) The total amount of cost to track with the budget.
- `notifications` (Attributes List) (Required) One or more notification objects. (see [below for nested schema](#nestedatt--csp_configuration--azure--subscriptions--management--budgets--notifications))

Optional:

- `time_grain` (String) (Optional) The time covered by a budget. Tracking of the amount will be reset based on the time grain. Must be one of BillingAnnual, BillingMonth, BillingQuarter, Annually, Monthly and Quarterly. Defaults to Monthly. Changing this forces a new resource to be created.

<a id="nestedatt--csp_configuration--azure--subscriptions--management--budgets--notifications"></a>
### Nested Schema for `csp_configuration.azure.subscriptions.management.budgets.time_grain`

Required:

- `contact_emails` (List of String) (Required) Specifies a list of email addresses to send the budget notification to when the threshold is exceeded.
- `threshold` (Number) (Required) Threshold value associated with a notification. Notification is sent when the cost exceeded the threshold. It is always percent and has to be between 0 and 1000.

Optional:

- `operator` (String) (Optional) The comparison operator for the notification. Must be one of EqualTo, GreaterThan, or GreaterThanOrEqualTo. Defaults to EqualTo.
- `threshold_type` (String) (Optional) The type of threshold for the notification. This determines whether the notification is triggered by forecasted costs or actual costs. The allowed values are Actual and Forecasted. Default is Actual. Changing this forces a new resource to be created.



<a id="nestedatt--csp_configuration--azure--subscriptions--management--ddos_protection_plan"></a>
### Nested Schema for `csp_configuration.azure.subscriptions.management.ddos_protection_plan`

Required:

- `enabled` (Boolean) (Required) Is Azure DDOS Protection Plan enabled?

Optional:

- `existing_ddos_protection_plan_resource_id` (String) (Optional) Existing Azure DDOS Protection Plan resource ID to be used.


<a id="nestedatt--csp_configuration--azure--subscriptions--management--dns_resolver"></a>
### Nested Schema for `csp_configuration.azure.subscriptions.management.dns_resolver`

Optional:

- `inbound` (Attributes) (Optional) Azure Private DNS Resolver Inbound Endpoint configuration. (see [below for nested schema](#nestedatt--csp_configuration--azure--subscriptions--management--dns_resolver--inbound))
- `outbound` (Attributes) (Optional) Azure Private DNS Resolver Outbound Endpoint configuration. (see [below for nested schema](#nestedatt--csp_configuration--azure--subscriptions--management--dns_resolver--outbound))

<a id="nestedatt--csp_configuration--azure--subscriptions--management--dns_resolver--inbound"></a>
### Nested Schema for `csp_configuration.azure.subscriptions.management.dns_resolver.outbound`

Optional:

- `enabled` (Boolean) (Optional) Is Azure Private DNS Resolver Inbound enpoint enabled?


<a id="nestedatt--csp_configuration--azure--subscriptions--management--dns_resolver--outbound"></a>
### Nested Schema for `csp_configuration.azure.subscriptions.management.dns_resolver.outbound`

Optional:

- `enabled` (Boolean) (Optional) Is Azure Private Resolver DNS Outbound enpoint enabled?
- `forwarding_domains` (Attributes List) (Optional) Provides a list of objects to configure outbound conditional forwarding. (see [below for nested schema](#nestedatt--csp_configuration--azure--subscriptions--management--dns_resolver--outbound--forwarding_domains))

<a id="nestedatt--csp_configuration--azure--subscriptions--management--dns_resolver--outbound--forwarding_domains"></a>
### Nested Schema for `csp_configuration.azure.subscriptions.management.dns_resolver.outbound.forwarding_domains`

Required:

- `dns_domain` (String) (Required) DNS domain for conditional forwarding.
- `dns_servers` (List of String) (Required) List of DNS servers that are authoritative for the domain.




<a id="nestedatt--csp_configuration--azure--subscriptions--management--dns_zones"></a>
### Nested Schema for `csp_configuration.azure.subscriptions.management.dns_zones`

Optional:

- `private_subdomains` (Attributes) (Optional) Map contains the private DNS domain for each environment. (see [below for nested schema](#nestedatt--csp_configuration--azure--subscriptions--management--dns_zones--private_subdomains))
- `public_domains` (List of String) (Optional) List contains the public DNS domains.

<a id="nestedatt--csp_configuration--azure--subscriptions--management--dns_zones--private_subdomains"></a>
### Nested Schema for `csp_configuration.azure.subscriptions.management.dns_zones.public_domains`

Optional:

- `dev` (String) (Optional) The subdomain name for creating the DEV environment private dns zone.
- `prod` (String) (Optional) The subdomain name for creating the PROD environment private dns zone.
- `qa` (String) (Optional) The subdomain name for creating the QA environment private dns zone.
- `test` (String) (Optional) The subdomain name for creating the TEST environment private dns zone.



<a id="nestedatt--csp_configuration--azure--subscriptions--management--hub_networks"></a>
### Nested Schema for `csp_configuration.azure.subscriptions.management.hub_networks`

Required:

- `enabled` (Boolean) (Required) If true, deploys a Hub and Spoke setup.

Optional:

- `azure_firewall` (Attributes) (Optional) Provides details for configuring Azure Firewall service. (see [below for nested schema](#nestedatt--csp_configuration--azure--subscriptions--management--hub_networks--azure_firewall))
- `azure_route_server` (Attributes) (Optional) Creates an Azure Route Server in the HUB VNET. (see [below for nested schema](#nestedatt--csp_configuration--azure--subscriptions--management--hub_networks--azure_route_server))
- `virtual_network_gateway` (Attributes) (Optional) Provides the details to create a new virtual network gateway. (see [below for nested schema](#nestedatt--csp_configuration--azure--subscriptions--management--hub_networks--virtual_network_gateway))

<a id="nestedatt--csp_configuration--azure--subscriptions--management--hub_networks--azure_firewall"></a>
### Nested Schema for `csp_configuration.azure.subscriptions.management.hub_networks.virtual_network_gateway`

Optional:

- `availability_zones` (Boolean) (Optional) Is Azure Firewall deployed across the 3 AZs? Defaults to true.
- `dns_proxy` (Boolean) (Optional) Is Azure Firewall going to act as a DNS Proxy? Defaults to true.
- `dns_servers` (List of String) (Optional) A list of DNS servers to configure on the Azure Firewall to use instead of Azure provided servers.
- `enabled` (Boolean) (Optional) Is Azure Firewall enabled? Defaults to true.
- `policy` (Attributes) (Optional) Configures Azure Firewall Policy. (see [below for nested schema](#nestedatt--csp_configuration--azure--subscriptions--management--hub_networks--virtual_network_gateway--policy))
- `sku` (String) (Optional) SKU tier of the Firewall. Possible values are Premium, Standard and Basic. Defaults to Standard.
- `threat_intelligence_mode` (String) (Optional) The operation mode for threat intelligence-based filtering. Possible values are: Off, Alert and Deny. Defaults to Alert.

<a id="nestedatt--csp_configuration--azure--subscriptions--management--hub_networks--virtual_network_gateway--policy"></a>
### Nested Schema for `csp_configuration.azure.subscriptions.management.hub_networks.virtual_network_gateway.threat_intelligence_mode`

Optional:

- `auto_learn_private_ranges_enabled` (Boolean) (Optional) If true, configures the Azure Firewalll to auto-learn SNAT IP prefixes. Defaults to true.



<a id="nestedatt--csp_configuration--azure--subscriptions--management--hub_networks--azure_route_server"></a>
### Nested Schema for `csp_configuration.azure.subscriptions.management.hub_networks.virtual_network_gateway`

Required:

- `enabled` (Boolean) (Required) If true, deploys an Azure Route Server in Hub VNET.

Optional:

- `attach_to_azure_firewall` (Boolean) (Optional) If true, configures the deployed Azure Firewall(deployed part of Hub network) to use this Route Server. Defaults to false.
- `bgp_connections` (Attributes List) (Optional) Provides a list of BGP Peer settings object. (see [below for nested schema](#nestedatt--csp_configuration--azure--subscriptions--management--hub_networks--virtual_network_gateway--bgp_connections))
- `branch_to_branch_traffic_enabled` (Boolean) (Optional) Whether to enable route exchange between Azure Route Server and the gateway(s). Defaults to false.
- `sku` (String) (Optional) The SKU of the Route Server. The only possible value is Standard. Changing this forces a new resource to be created. Defaults to Standard.

<a id="nestedatt--csp_configuration--azure--subscriptions--management--hub_networks--virtual_network_gateway--bgp_connections"></a>
### Nested Schema for `csp_configuration.azure.subscriptions.management.hub_networks.virtual_network_gateway.sku`

Required:

- `peer_asn` (Number) (Required) The BGP ASN number of the peer.
- `peer_geo` (String) (Required) The Geography Key (as defined in the geographies object under tenancy resource) where the peer needs to be configured.
- `peer_ip` (String) (Required) The IP address of the peer.
- `peer_name` (String) (Required) The name of the peer.
- `peer_region` (String) (Required) The Region Key (primary/secondary) where the peer needs to be configured.



<a id="nestedatt--csp_configuration--azure--subscriptions--management--hub_networks--virtual_network_gateway"></a>
### Nested Schema for `csp_configuration.azure.subscriptions.management.hub_networks.virtual_network_gateway`

Required:

- `enabled` (Boolean) (Required) Is Azure Virtual Network Gateway enabled?

Optional:

- `s2s_vpns` (Attributes List) (Optional) Provides a list of objects, each object has configuration for a site-to-site VPN with a remote gateway. (see [below for nested schema](#nestedatt--csp_configuration--azure--subscriptions--management--hub_networks--virtual_network_gateway--s2s_vpns))
- `sku` (String) (Optional) Configuration of the size and capacity of the virtual network gateway. Valid options are Basic, Standard, HighPerformance, UltraPerformance, ErGw1AZ, ErGw2AZ, ErGw3AZ, VpnGw1, VpnGw2, VpnGw3, VpnGw4,VpnGw5, VpnGw1AZ, VpnGw2AZ, VpnGw3AZ,VpnGw4AZ and VpnGw5AZ and depend on the type, vpn_type and generation arguments. A PolicyBased gateway only supports the Basic SKU. Further, the UltraPerformance SKU is only supported by an ExpressRoute gateway. Defaults to Basic.
- `type` (String) (Optional) The type of the Virtual Network Gateway. Valid options are Vpn or ExpressRoute. Defaults to Vpn. Changing the type forces a new resource to be created.
- `vpn_type` (String) (Optional) The routing type of the Virtual Network Gateway. Valid options are RouteBased or PolicyBased. Defaults to RouteBased. Changing this forces a new resource to be created.

<a id="nestedatt--csp_configuration--azure--subscriptions--management--hub_networks--virtual_network_gateway--s2s_vpns"></a>
### Nested Schema for `csp_configuration.azure.subscriptions.management.hub_networks.virtual_network_gateway.vpn_type`

Required:

- `gateway_name` (String) (Required) The name of the local network gateway. Changing this forces a new resource to be created.

Optional:

- `connection_bgp_custom_addresses` (Attributes) (Optional) Provides connection BGP Protocol custom addresses. (see [below for nested schema](#nestedatt--csp_configuration--azure--subscriptions--management--hub_networks--virtual_network_gateway--vpn_type--connection_bgp_custom_addresses))
- `connection_dpd_timeout_seconds` (Number) (Optional) The dead peer detection timeout of this connection in seconds. Changing this forces a new resource to be created.
- `connection_egress_nat_rule_ids` (List of String) (Optional) A list of the egress NAT Rule Ids.
- `connection_ingress_nat_rule_ids` (List of String) (Optional) A list of the ingress NAT Rule Ids.
- `connection_ipsec_policy` (Attributes) (Optional) A ipsec_policy object. Only a single policy can be defined for a connection. For details on custom policies refer to the relevant section in the Azure documentation. (see [below for nested schema](#nestedatt--csp_configuration--azure--subscriptions--management--hub_networks--virtual_network_gateway--vpn_type--connection_ipsec_policy))
- `connection_local_azure_ip_address_enabled` (Boolean) (Optional) Use private local Azure IP for the connection. Changing this forces a new resource to be created.
- `connection_mode` (String) (Optional) Connection mode to use. Possible values are Default, InitiatorOnly and ResponderOnly. Defaults to Default. Changing this value will force a resource to be created.
- `connection_protocol` (String) (Optional) The IKE protocol version to use. Possible values are IKEv1 and IKEv2. Defaults to IKEv2. Changing this forces a new resource to be created. -> Note: Only valid for IPSec connections on virtual network gateways with SKU VpnGw1, VpnGw2, VpnGw3, VpnGw1AZ, VpnGw2AZ or VpnGw3AZ.
- `connection_type` (String) (Optional) The type of connection. Valid options are IPsec (Site-to-Site), ExpressRoute (ExpressRoute), and Vnet2Vnet (VNet-to-VNet). Each connection type requires different mandatory arguments (refer to the examples above). Defaults to IPSec. Changing this forces a new resource to be created.
- `gateway_address` (String) (Optional) The gateway IP address to connect with.
- `gateway_address_space` (List of String) (Optional) The list of string CIDRs representing the address spaces the gateway exposes.
- `gateway_bpg_settings` (Attributes) (Optional) A bgp_settings containing the Local Network Gateway's BGP speaker settings. (see [below for nested schema](#nestedatt--csp_configuration--azure--subscriptions--management--hub_networks--virtual_network_gateway--vpn_type--gateway_bpg_settings))
- `gateway_fqdn` (String) (Optional) The gateway FQDN to connect with.

<a id="nestedatt--csp_configuration--azure--subscriptions--management--hub_networks--virtual_network_gateway--vpn_type--connection_bgp_custom_addresses"></a>
### Nested Schema for `csp_configuration.azure.subscriptions.management.hub_networks.virtual_network_gateway.vpn_type.gateway_fqdn`

Required:

- `primary` (String) (Required) single IP address that is part of the azurerm_virtual_network_gateway ip_configuration (first one)
- `secondary` (String) (Required) single IP address that is part of the azurerm_virtual_network_gateway ip_configuration (second one)


<a id="nestedatt--csp_configuration--azure--subscriptions--management--hub_networks--virtual_network_gateway--vpn_type--connection_ipsec_policy"></a>
### Nested Schema for `csp_configuration.azure.subscriptions.management.hub_networks.virtual_network_gateway.vpn_type.gateway_fqdn`

Optional:

- `dh_group` (String) (Optional) The DH group used in IKE phase 1 for initial SA. Valid options are DHGroup1, DHGroup14, DHGroup2, DHGroup2048, DHGroup24, ECP256, ECP384, or None. Defaults to DHGroup2.
- `ike_encryption` (String) (Optional) The IKE encryption algorithm. Valid options are AES128, AES192, AES256, DES, DES3, GCMAES128, or GCMAES256. Defaults to AES256.
- `ike_integrity` (String) (Optional) The IKE integrity algorithm. Valid options are GCMAES128, GCMAES256, MD5, SHA1, SHA256, or SHA384. Defaults to SHA256.
- `ipsec_encryption` (String) (Optional) The IPSec encryption algorithm. Valid options are AES128, AES192, AES256, DES, DES3, GCMAES128, GCMAES192, GCMAES256, or None. Defaults to AES256.
- `ipsec_integrity` (String) (Optional) The IPSec integrity algorithm. Valid options are GCMAES128, GCMAES192, GCMAES256, MD5, SHA1, or SHA256. Defaults to SHA256.
- `pfs_group` (String) (Optional) The DH group used in IKE phase 2 for new child SA. Valid options are ECP256, ECP384, PFS1, PFS14, PFS2, PFS2048, PFS24, PFSMM, or None. Defaults to PFS2.
- `sa_datasize` (Number) (Optional) The IPSec SA payload size in KB. Must be at least 1024 KB. Defaults to 102400000 KB.
- `sa_lifetime` (Number) (Optional) The IPSec SA lifetime in seconds. Must be at least 300 seconds. Defaults to 27000 seconds.


<a id="nestedatt--csp_configuration--azure--subscriptions--management--hub_networks--virtual_network_gateway--vpn_type--gateway_bpg_settings"></a>
### Nested Schema for `csp_configuration.azure.subscriptions.management.hub_networks.virtual_network_gateway.vpn_type.gateway_fqdn`

Required:

- `asn` (String) (Required) The BGP speaker's ASN.
- `peering_address` (String) (Required) The BGP peering address and BGP identifier of this BGP speaker.

Optional:

- `peer_weight` (String) (Optional) The weight added to routes learned from this BGP speaker.





<a id="nestedatt--csp_configuration--azure--subscriptions--management--keyvault"></a>
### Nested Schema for `csp_configuration.azure.subscriptions.management.keyvault`

Optional:

- `purge_protection_enabled` (Boolean) (Optional) Is Purge Protection enabled for this Key Vault? Defaults to true.
- `sku` (String) (Optional) The Name of the SKU used for this Key Vault. Possible values are standard and premium. Defaults to standard.
- `soft_delete_retention_days` (Number) (Optional) The number of days that items should be retained for once soft-deleted. This field can only be configured one time and cannot be updated. This value can be between 7 and 90 days. Defaults to 90.


<a id="nestedatt--csp_configuration--azure--subscriptions--management--resource_groups_lock"></a>
### Nested Schema for `csp_configuration.azure.subscriptions.management.resource_groups_lock`

Optional:

- `baseline` (Boolean) (Optional) Boolean flag to enable/disable RG lock. Defaults to true.
- `ddos` (Boolean) (Optional) Boolean flag to enable/disable RG lock. Defaults to false.
- `dns` (Boolean) (Optional) Boolean flag to enable/disable RG lock. Defaults to false.
- `rsv` (Boolean) (Optional) Boolean flag to enable/disable RG lock. Defaults to false.


<a id="nestedatt--csp_configuration--azure--subscriptions--management--vwan_hub_networks"></a>
### Nested Schema for `csp_configuration.azure.subscriptions.management.vwan_hub_networks`

Required:

- `enabled` (Boolean) (Required) If true, deploys a VWAN setup.

Optional:

- `azure_firewall` (Attributes) (Optional) Provides details for configuring Azure Firewall service. (see [below for nested schema](#nestedatt--csp_configuration--azure--subscriptions--management--vwan_hub_networks--azure_firewall))
- `existing_virtual_wan_resource_id` (String) (Optional) Existing Virtual WAN resource ID to be used.
- `expressroute_gateway` (Attributes) (Optional) Manages an ExpressRoute gateway within a Virtual WAN. (see [below for nested schema](#nestedatt--csp_configuration--azure--subscriptions--management--vwan_hub_networks--expressroute_gateway))
- `routes` (Attributes List) (Optional) One or more route objects as defined below. (see [below for nested schema](#nestedatt--csp_configuration--azure--subscriptions--management--vwan_hub_networks--routes))
- `vpn_gateway` (Attributes) (Optional) Manages a VPN Gateway within a Virtual Hub, which enables Site-to-Site communication. (see [below for nested schema](#nestedatt--csp_configuration--azure--subscriptions--management--vwan_hub_networks--vpn_gateway))

<a id="nestedatt--csp_configuration--azure--subscriptions--management--vwan_hub_networks--azure_firewall"></a>
### Nested Schema for `csp_configuration.azure.subscriptions.management.vwan_hub_networks.vpn_gateway`

Optional:

- `availability_zones` (Boolean) (Optional) Is Azure Firewall deployed across the 3 AZs? Defaults to true.
- `dns_proxy` (Boolean) (Optional) Is Azure Firewall going to act as a DNS Proxy? Defaults to true.
- `dns_servers` (List of String) (Optional) A list of DNS servers to configure on the Azure Firewall to use instead of Azure provided servers.
- `enabled` (Boolean) (Optional) Is Azure Firewall enabled? Defaults to true.
- `sku` (String) (Optional) SKU tier of the Firewall. Possible values are Premium, Standard and Basic. Defaults to Standard.
- `threat_intelligence_mode` (String) (Optional) The operation mode for threat intelligence-based filtering. Possible values are: Off, Alert and Deny. Defaults to Alert.


<a id="nestedatt--csp_configuration--azure--subscriptions--management--vwan_hub_networks--expressroute_gateway"></a>
### Nested Schema for `csp_configuration.azure.subscriptions.management.vwan_hub_networks.vpn_gateway`

Required:

- `enabled` (Boolean) (Required) If true, deploys Expressroute Gateway.

Optional:

- `scale_unit` (Number) (Optional) The number of scale units with which to provision the ExpressRoute gateway. Each scale unit is equal to 2Gbps, with support for up to 10 scale units (20Gbps). Defaults to `1`


<a id="nestedatt--csp_configuration--azure--subscriptions--management--vwan_hub_networks--routes"></a>
### Nested Schema for `csp_configuration.azure.subscriptions.management.vwan_hub_networks.vpn_gateway`

Required:

- `address_prefixes` (List of String) (Required) A list of Address Prefixes.
- `next_hop_ip_address` (String) (Required) The IP Address that Packets should be forwarded to as the Next Hop.


<a id="nestedatt--csp_configuration--azure--subscriptions--management--vwan_hub_networks--vpn_gateway"></a>
### Nested Schema for `csp_configuration.azure.subscriptions.management.vwan_hub_networks.vpn_gateway`

Required:

- `enabled` (Boolean) (Required) If true, deploys VPN Gateway.

Optional:

- `bgp_settings` (Attributes) (Optional) A bgp_settings object. (see [below for nested schema](#nestedatt--csp_configuration--azure--subscriptions--management--vwan_hub_networks--vpn_gateway--bgp_settings))
- `routing_preference` (String) (Optional) Azure routing preference lets you to choose how your traffic routes between Azure and the internet. You can choose to route traffic either via the `Microsoft Network` or via the ISP network, `Internet`. Defaults to `Microsoft Network`.
- `scale_unit` (Number) (Optional) The number of scale units with which to provision the VPN gateway. Each scale unit is equal to 2Gbps, with support for up to 10 scale units (20Gbps). Defaults to `1`

<a id="nestedatt--csp_configuration--azure--subscriptions--management--vwan_hub_networks--vpn_gateway--bgp_settings"></a>
### Nested Schema for `csp_configuration.azure.subscriptions.management.vwan_hub_networks.vpn_gateway.scale_unit`

Required:

- `asn` (Number) (Required) The ASN of the BGP Speaker. Changing this forces a new resource to be created.
- `peer_weight` (Number) (Required) The weight added to Routes learned from this BGP Speaker. Changing this forces a new resource to be created.

Optional:

- `instance_0_bgp_peering_address` (Attributes List) (Optional) An instance_bgp_peering_address object. (see [below for nested schema](#nestedatt--csp_configuration--azure--subscriptions--management--vwan_hub_networks--vpn_gateway--scale_unit--instance_0_bgp_peering_address))
- `instance_1_bgp_peering_address` (Attributes List) (Optional) An instance_bgp_peering_address object. (see [below for nested schema](#nestedatt--csp_configuration--azure--subscriptions--management--vwan_hub_networks--vpn_gateway--scale_unit--instance_1_bgp_peering_address))

<a id="nestedatt--csp_configuration--azure--subscriptions--management--vwan_hub_networks--vpn_gateway--scale_unit--instance_0_bgp_peering_address"></a>
### Nested Schema for `csp_configuration.azure.subscriptions.management.vwan_hub_networks.vpn_gateway.scale_unit.instance_1_bgp_peering_address`

Required:

- `custom_ips` (List of String) (Required) A list of custom BGP peering addresses to assign to this instance.


<a id="nestedatt--csp_configuration--azure--subscriptions--management--vwan_hub_networks--vpn_gateway--scale_unit--instance_1_bgp_peering_address"></a>
### Nested Schema for `csp_configuration.azure.subscriptions.management.vwan_hub_networks.vpn_gateway.scale_unit.instance_1_bgp_peering_address`

Required:

- `custom_ips` (List of String) (Required) A list of custom BGP peering addresses to assign to this instance.






<a id="nestedatt--csp_configuration--azure--subscriptions--identity"></a>
### Nested Schema for `csp_configuration.azure.subscriptions.management`

Required:

- `abbreviation` (String) (Required) This abbreviation will be used to uniquily identify resources created in this subscription. Only applies to resources that require Azure global uniqueness.

Optional:

- `azuread_domain_services` (Attributes) (Optional) Azure AD Domain Services configuration details. (see [below for nested schema](#nestedatt--csp_configuration--azure--subscriptions--management--azuread_domain_services))
- `budgets` (Attributes List) (Optional) Provides a list of budget objects. (see [below for nested schema](#nestedatt--csp_configuration--azure--subscriptions--management--budgets))
- `keyvault` (Attributes) (Optional) Azure KeyVault configuration details. (see [below for nested schema](#nestedatt--csp_configuration--azure--subscriptions--management--keyvault))
- `resource_groups_lock` (Attributes) (Optional) Configures Azure Delete Lock at Resource Groups level. (see [below for nested schema](#nestedatt--csp_configuration--azure--subscriptions--management--resource_groups_lock))
- `vnet` (Attributes) (Optional) Settings for customizing standard subnets and adding PaaS subnets. (see [below for nested schema](#nestedatt--csp_configuration--azure--subscriptions--management--vnet))

<a id="nestedatt--csp_configuration--azure--subscriptions--management--azuread_domain_services"></a>
### Nested Schema for `csp_configuration.azure.subscriptions.management.azuread_domain_services`

Optional:

- `admin_vm` (Attributes) (Optional) Provides configuration details for AAD DS Admin VM. (see [below for nested schema](#nestedatt--csp_configuration--azure--subscriptions--management--azuread_domain_services--admin_vm))
- `enabled` (Boolean) (Oprional) Boolean flag to enable/disable AzureAD Domain Services. Defaults to false.
- `notification_recipients` (List of String) (Optional) Provides a list of email addresses to receive notifications from Azure AD Domain Services.
- `sku` (String) (Optional) The SKU to use when provisioning the Domain Service resource. One of Standard, Enterprise or Premium. Defaults to Standard.

<a id="nestedatt--csp_configuration--azure--subscriptions--management--azuread_domain_services--admin_vm"></a>
### Nested Schema for `csp_configuration.azure.subscriptions.management.azuread_domain_services.sku`

Optional:

- `admin_username` (String) (Optional) Provides a username for the local admin of the Admin VM. Defaults to local.admin.
- `computer_name` (String) (Optional) Provides a computer name for the Admin VM. Defaults to aaddsadmin.
- `enabled` (Boolean) (Optional) If true, it will create an Admin VM based on Windows 10 for Azure AD Domain Services and join it into the AD domain. Defaults to false.
- `shutdown_schedule_notification_email` (String) (Optional) Email address to receive notification of shutdown 30 min before a shutdown event.
- `shutdown_schedule_recurrence_time` (String) (Optional) The time each day when the schedule takes effect in UTC timezone. Must match the format HHmm where HH is 00-23 and mm is 00-59 (e.g. 0930, 2300, etc.). Defaults to 0000 UTC.



<a id="nestedatt--csp_configuration--azure--subscriptions--management--budgets"></a>
### Nested Schema for `csp_configuration.azure.subscriptions.management.budgets`

Required:

- `amount` (Number) (Required) The total amount of cost to track with the budget.
- `notifications` (Attributes List) (Required) One or more notification objects. (see [below for nested schema](#nestedatt--csp_configuration--azure--subscriptions--management--budgets--notifications))

Optional:

- `time_grain` (String) (Optional) The time covered by a budget. Tracking of the amount will be reset based on the time grain. Must be one of BillingAnnual, BillingMonth, BillingQuarter, Annually, Monthly and Quarterly. Defaults to Monthly. Changing this forces a new resource to be created.

<a id="nestedatt--csp_configuration--azure--subscriptions--management--budgets--notifications"></a>
### Nested Schema for `csp_configuration.azure.subscriptions.management.budgets.time_grain`

Required:

- `contact_emails` (List of String) (Required) Specifies a list of email addresses to send the budget notification to when the threshold is exceeded.
- `threshold` (Number) (Required) Threshold value associated with a notification. Notification is sent when the cost exceeded the threshold. It is always percent and has to be between 0 and 1000.

Optional:

- `operator` (String) (Optional) The comparison operator for the notification. Must be one of EqualTo, GreaterThan, or GreaterThanOrEqualTo. Defaults to EqualTo.
- `threshold_type` (String) (Optional) The type of threshold for the notification. This determines whether the notification is triggered by forecasted costs or actual costs. The allowed values are Actual and Forecasted. Default is Actual. Changing this forces a new resource to be created.



<a id="nestedatt--csp_configuration--azure--subscriptions--management--keyvault"></a>
### Nested Schema for `csp_configuration.azure.subscriptions.management.keyvault`

Optional:

- `purge_protection_enabled` (Boolean) (Optional) Is Purge Protection enabled for this Key Vault? Defaults to true.
- `sku` (String) (Optional) The Name of the SKU used for this Key Vault. Possible values are standard and premium. Defaults to standard.
- `soft_delete_retention_days` (Number) (Optional) The number of days that items should be retained for once soft-deleted. This field can only be configured one time and cannot be updated. This value can be between 7 and 90 days. Defaults to 90.


<a id="nestedatt--csp_configuration--azure--subscriptions--management--resource_groups_lock"></a>
### Nested Schema for `csp_configuration.azure.subscriptions.management.resource_groups_lock`

Optional:

- `baseline` (Boolean) (Optional) Boolean flag to enable/disable RG lock. Defaults to true.
- `rsv` (Boolean) (Optional) Boolean flag to enable/disable RG lock. Defaults to false.


<a id="nestedatt--csp_configuration--azure--subscriptions--management--vnet"></a>
### Nested Schema for `csp_configuration.azure.subscriptions.management.vnet`

Optional:

- `subnets` (Attributes) (Optional) Configure subnets. (see [below for nested schema](#nestedatt--csp_configuration--azure--subscriptions--management--vnet--subnets))
- `vnet_link_to_private_dns_zones` (List of String) (Optional) Provides a list of Azure Private DNS Zones to link to this VNET. The zones must be zones created by the volocloud provider: either PaaS private zones or custom private zones.

<a id="nestedatt--csp_configuration--azure--subscriptions--management--vnet--subnets"></a>
### Nested Schema for `csp_configuration.azure.subscriptions.management.vnet.vnet_link_to_private_dns_zones`

Optional:

- `standard` (Attributes) (Optional) Configure standard subnets. (see [below for nested schema](#nestedatt--csp_configuration--azure--subscriptions--management--vnet--vnet_link_to_private_dns_zones--standard))

<a id="nestedatt--csp_configuration--azure--subscriptions--management--vnet--vnet_link_to_private_dns_zones--standard"></a>
### Nested Schema for `csp_configuration.azure.subscriptions.management.vnet.vnet_link_to_private_dns_zones.standard`

Optional:

- `aadds` (Attributes) (Optional) Configures Azure Active Direction Domain Services subnet. (see [below for nested schema](#nestedatt--csp_configuration--azure--subscriptions--management--vnet--vnet_link_to_private_dns_zones--standard--aadds))
- `controlled` (Attributes) (Optional) Configures Controlled standard subnet. (see [below for nested schema](#nestedatt--csp_configuration--azure--subscriptions--management--vnet--vnet_link_to_private_dns_zones--standard--controlled))

<a id="nestedatt--csp_configuration--azure--subscriptions--management--vnet--vnet_link_to_private_dns_zones--standard--aadds"></a>
### Nested Schema for `csp_configuration.azure.subscriptions.management.vnet.vnet_link_to_private_dns_zones.standard.controlled`

Optional:

- `service_endpoints` (List of String) (Optional) The list of Service endpoints to associate with the subnet.


<a id="nestedatt--csp_configuration--azure--subscriptions--management--vnet--vnet_link_to_private_dns_zones--standard--controlled"></a>
### Nested Schema for `csp_configuration.azure.subscriptions.management.vnet.vnet_link_to_private_dns_zones.standard.controlled`

Optional:

- `delegation` (Attributes) (Optional) Provides details to deleted the subnet to a supported Azure service. (see [below for nested schema](#nestedatt--csp_configuration--azure--subscriptions--management--vnet--vnet_link_to_private_dns_zones--standard--controlled--delegation))
- `service_endpoints` (List of String) (Optional) The list of Service endpoints to associate with the subnet.

<a id="nestedatt--csp_configuration--azure--subscriptions--management--vnet--vnet_link_to_private_dns_zones--standard--controlled--delegation"></a>
### Nested Schema for `csp_configuration.azure.subscriptions.management.vnet.vnet_link_to_private_dns_zones.standard.controlled.delegation`

Required:

- `name` (String) (Required) A name for this delegation.
- `service` (String) (Required) The name of service to delegate to.

Optional:

- `actions` (List of String) (Optional) A list of Actions which should be delegated. This list is specific to the service to delegate to.







<a id="nestedatt--csp_configuration--azure--subscriptions--management"></a>
### Nested Schema for `csp_configuration.azure.subscriptions.management`

Required:

- `abbreviation` (String) (Required) This abbreviation will be used to uniquily identify resources created in this subscription. Only applies to resources that require Azure global uniqueness.
- `mdfc` (Attributes) (Required) Configures Microsoft Defender for Cloud service. (see [below for nested schema](#nestedatt--csp_configuration--azure--subscriptions--management--mdfc))

Optional:

- `automation_account` (Attributes) (Optional) Automation Account configuration details. (see [below for nested schema](#nestedatt--csp_configuration--azure--subscriptions--management--automation_account))
- `budgets` (Attributes List) (Optional) Provides a list of budget objects. (see [below for nested schema](#nestedatt--csp_configuration--azure--subscriptions--management--budgets))
- `keyvault` (Attributes) (Optional) Azure KeyVault configuration details. (see [below for nested schema](#nestedatt--csp_configuration--azure--subscriptions--management--keyvault))
- `log_analytics` (Attributes) (Optional) Log Analytics Workspace configuration. (see [below for nested schema](#nestedatt--csp_configuration--azure--subscriptions--management--log_analytics))
- `network_watcher_flow_logs` (Attributes) (Optional) Network Watcher Flow Logs configuration details. (see [below for nested schema](#nestedatt--csp_configuration--azure--subscriptions--management--network_watcher_flow_logs))
- `private_agent` (Attributes) (Optional) Enables the use of Terraform Cloud private agent deployed in the target environment. This agent enables management of private resources not available on the internet. It had impact on the cost of the Volo LZ subscription. (see [below for nested schema](#nestedatt--csp_configuration--azure--subscriptions--management--private_agent))
- `resource_groups_lock` (Attributes) (Optional) Configures Azure Delete Lock at Resource Groups level. (see [below for nested schema](#nestedatt--csp_configuration--azure--subscriptions--management--resource_groups_lock))
- `vnet` (Attributes) (Optional) Settings for customizing standard subnets and adding PaaS subnets. (see [below for nested schema](#nestedatt--csp_configuration--azure--subscriptions--management--vnet))

<a id="nestedatt--csp_configuration--azure--subscriptions--management--mdfc"></a>
### Nested Schema for `csp_configuration.azure.subscriptions.management.mdfc`

Required:

- `email` (String) (Required) Email address to receive alerts from MDFC.

Optional:

- `services` (List of String) (Optional) Provides a list of MDFC services to enable. If not provided, all services are enabled by default. To disable all services, provide an empty list.


<a id="nestedatt--csp_configuration--azure--subscriptions--management--automation_account"></a>
### Nested Schema for `csp_configuration.azure.subscriptions.management.automation_account`

Optional:

- `sku` (String) (Optional) The SKU of the account. Possible values are Basic and Free. Defaults to Basic.


<a id="nestedatt--csp_configuration--azure--subscriptions--management--budgets"></a>
### Nested Schema for `csp_configuration.azure.subscriptions.management.budgets`

Required:

- `amount` (Number) (Required) The total amount of cost to track with the budget.
- `notifications` (Attributes List) (Required) One or more notification objects. (see [below for nested schema](#nestedatt--csp_configuration--azure--subscriptions--management--budgets--notifications))

Optional:

- `time_grain` (String) (Optional) The time covered by a budget. Tracking of the amount will be reset based on the time grain. Must be one of BillingAnnual, BillingMonth, BillingQuarter, Annually, Monthly and Quarterly. Defaults to Monthly. Changing this forces a new resource to be created.

<a id="nestedatt--csp_configuration--azure--subscriptions--management--budgets--notifications"></a>
### Nested Schema for `csp_configuration.azure.subscriptions.management.budgets.time_grain`

Required:

- `contact_emails` (List of String) (Required) Specifies a list of email addresses to send the budget notification to when the threshold is exceeded.
- `threshold` (Number) (Required) Threshold value associated with a notification. Notification is sent when the cost exceeded the threshold. It is always percent and has to be between 0 and 1000.

Optional:

- `operator` (String) (Optional) The comparison operator for the notification. Must be one of EqualTo, GreaterThan, or GreaterThanOrEqualTo. Defaults to EqualTo.
- `threshold_type` (String) (Optional) The type of threshold for the notification. This determines whether the notification is triggered by forecasted costs or actual costs. The allowed values are Actual and Forecasted. Default is Actual. Changing this forces a new resource to be created.



<a id="nestedatt--csp_configuration--azure--subscriptions--management--keyvault"></a>
### Nested Schema for `csp_configuration.azure.subscriptions.management.keyvault`

Optional:

- `purge_protection_enabled` (Boolean) (Optional) Is Purge Protection enabled for this Key Vault? Defaults to true.
- `sku` (String) (Optional) The Name of the SKU used for this Key Vault. Possible values are standard and premium. Defaults to standard.
- `soft_delete_retention_days` (Number) (Optional) The number of days that items should be retained for once soft-deleted. This field can only be configured one time and cannot be updated. This value can be between 7 and 90 days. Defaults to 90.


<a id="nestedatt--csp_configuration--azure--subscriptions--management--log_analytics"></a>
### Nested Schema for `csp_configuration.azure.subscriptions.management.log_analytics`

Optional:

- `daily_quota_gb` (Number) (Optional) The workspace daily quota for ingestion in GB. Defaults to -1 (unlimited).
- `internet_ingestion_enabled` (Boolean) (Optional) Should the Log Analytics Workspace support ingestion over the Public Internet? Defaults to true.
- `internet_query_enabled` (Boolean) (Optional) Should the Log Analytics Workspace support querying over the Public Internet? Defaults to true.
- `reservation_capacity_in_gb_per_day` (Number) (Optional) The capacity reservation level in GB for this workspace. Must be in increments of 100 between 100 and 5000.
- `retention_in_days` (Number) (Optional) The workspace data retention in days. Possible values are either 7 (Free Tier only) or range between 30 and 730. Defaults to 30.
- `sku` (String) (Optional) Specifies the SKU of the Log Analytics Workspace. Possible values are Free, PerNode, Premium, Standard, Standalone, Unlimited, CapacityReservation, and PerGB2018 (new SKU as of 2018-04-03). Defaults to PerGB2018.
- `solutions` (List of String) (Optional) List of solutions to deploy to the Log Analytics Workspace. Defaults to ["solution_for_azure_activity", "solution_for_change_tracking", "solution_for_updates"]


<a id="nestedatt--csp_configuration--azure--subscriptions--management--network_watcher_flow_logs"></a>
### Nested Schema for `csp_configuration.azure.subscriptions.management.network_watcher_flow_logs`

Optional:

- `retention_policy` (Attributes) (Optional) A retention_policy object. (see [below for nested schema](#nestedatt--csp_configuration--azure--subscriptions--management--network_watcher_flow_logs--retention_policy))
- `traffic_analytics` (Attributes) (Optional) A traffic_analytics object. (see [below for nested schema](#nestedatt--csp_configuration--azure--subscriptions--management--network_watcher_flow_logs--traffic_analytics))

<a id="nestedatt--csp_configuration--azure--subscriptions--management--network_watcher_flow_logs--retention_policy"></a>
### Nested Schema for `csp_configuration.azure.subscriptions.management.network_watcher_flow_logs.traffic_analytics`

Optional:

- `days` (Number) (Optional) The number of days to retain flow log records. Defaults to 30 days.
- `enabled` (Boolean) (Oprional) Boolean flag to enable/disable retention. Defaults to true.


<a id="nestedatt--csp_configuration--azure--subscriptions--management--network_watcher_flow_logs--traffic_analytics"></a>
### Nested Schema for `csp_configuration.azure.subscriptions.management.network_watcher_flow_logs.traffic_analytics`

Optional:

- `enabled` (Boolean) (Oprional) Boolean flag to enable/disable traffic analytics. Defaults to false.
- `interval_in_minutes` (Number) (Optional) How frequently service should do flow analytics in minutes. Defaults to 60.



<a id="nestedatt--csp_configuration--azure--subscriptions--management--private_agent"></a>
### Nested Schema for `csp_configuration.azure.subscriptions.management.private_agent`

Optional:

- `availability_zones` (List of String) (Optional) The number of terraform private agents to deploy, one per Azure Availability Zone. If the Azure region doesn't support Availability Zones then leave this null, otherwise the resources will fail to create.
- `enabled` (Boolean) (Optional) Boolean flag to enable/disable terraform private agent. Defaults to false.


<a id="nestedatt--csp_configuration--azure--subscriptions--management--resource_groups_lock"></a>
### Nested Schema for `csp_configuration.azure.subscriptions.management.resource_groups_lock`

Optional:

- `baseline` (Boolean) (Optional) Boolean flag to enable/disable RG lock. Defaults to true.
- `rsv` (Boolean) (Optional) Boolean flag to enable/disable RG lock. Defaults to false.


<a id="nestedatt--csp_configuration--azure--subscriptions--management--vnet"></a>
### Nested Schema for `csp_configuration.azure.subscriptions.management.vnet`

Optional:

- `subnets` (Attributes) (Optional) Configure subnets. (see [below for nested schema](#nestedatt--csp_configuration--azure--subscriptions--management--vnet--subnets))
- `vnet_link_to_private_dns_zones` (List of String) (Optional) Provides a list of Azure Private DNS Zones to link to this VNET. The zones must be zones created by the volocloud provider: either PaaS private zones or custom private zones.

<a id="nestedatt--csp_configuration--azure--subscriptions--management--vnet--subnets"></a>
### Nested Schema for `csp_configuration.azure.subscriptions.management.vnet.vnet_link_to_private_dns_zones`

Optional:

- `paas` (Attributes) (Optional) Configure PaaS subnets. (see [below for nested schema](#nestedatt--csp_configuration--azure--subscriptions--management--vnet--vnet_link_to_private_dns_zones--paas))
- `standard` (Attributes) (Optional) Configure standard subnets. (see [below for nested schema](#nestedatt--csp_configuration--azure--subscriptions--management--vnet--vnet_link_to_private_dns_zones--standard))

<a id="nestedatt--csp_configuration--azure--subscriptions--management--vnet--vnet_link_to_private_dns_zones--paas"></a>
### Nested Schema for `csp_configuration.azure.subscriptions.management.vnet.vnet_link_to_private_dns_zones.standard`

Optional:

- `agw` (Attributes) (Optional) Configures PaaS subnet for Application Gateway. (see [below for nested schema](#nestedatt--csp_configuration--azure--subscriptions--management--vnet--vnet_link_to_private_dns_zones--standard--agw))

<a id="nestedatt--csp_configuration--azure--subscriptions--management--vnet--vnet_link_to_private_dns_zones--standard--agw"></a>
### Nested Schema for `csp_configuration.azure.subscriptions.management.vnet.vnet_link_to_private_dns_zones.standard.agw`

Required:

- `enabled` (Boolean) (Required) If true, deploys a PaaS subnet in the VNET.

Optional:

- `service_endpoints` (List of String) (Optional) The list of Service endpoints to associate with the subnet.



<a id="nestedatt--csp_configuration--azure--subscriptions--management--vnet--vnet_link_to_private_dns_zones--standard"></a>
### Nested Schema for `csp_configuration.azure.subscriptions.management.vnet.vnet_link_to_private_dns_zones.standard`

Optional:

- `controlled` (Attributes) (Optional) Configures Controlled standard subnet. (see [below for nested schema](#nestedatt--csp_configuration--azure--subscriptions--management--vnet--vnet_link_to_private_dns_zones--standard--controlled))
- `dmz` (Attributes) (Optional) Configures DMZ standard subnet. (see [below for nested schema](#nestedatt--csp_configuration--azure--subscriptions--management--vnet--vnet_link_to_private_dns_zones--standard--dmz))
- `secured` (Attributes) (Optional) Configures Secured standard subnet. (see [below for nested schema](#nestedatt--csp_configuration--azure--subscriptions--management--vnet--vnet_link_to_private_dns_zones--standard--secured))

<a id="nestedatt--csp_configuration--azure--subscriptions--management--vnet--vnet_link_to_private_dns_zones--standard--controlled"></a>
### Nested Schema for `csp_configuration.azure.subscriptions.management.vnet.vnet_link_to_private_dns_zones.standard.secured`

Optional:

- `delegation` (Attributes) (Optional) Provides details to deleted the subnet to a supported Azure service. (see [below for nested schema](#nestedatt--csp_configuration--azure--subscriptions--management--vnet--vnet_link_to_private_dns_zones--standard--secured--delegation))
- `service_endpoints` (List of String) (Optional) The list of Service endpoints to associate with the subnet.

<a id="nestedatt--csp_configuration--azure--subscriptions--management--vnet--vnet_link_to_private_dns_zones--standard--secured--delegation"></a>
### Nested Schema for `csp_configuration.azure.subscriptions.management.vnet.vnet_link_to_private_dns_zones.standard.secured.delegation`

Required:

- `name` (String) (Required) A name for this delegation.
- `service` (String) (Required) The name of service to delegate to.

Optional:

- `actions` (List of String) (Optional) A list of Actions which should be delegated. This list is specific to the service to delegate to.



<a id="nestedatt--csp_configuration--azure--subscriptions--management--vnet--vnet_link_to_private_dns_zones--standard--dmz"></a>
### Nested Schema for `csp_configuration.azure.subscriptions.management.vnet.vnet_link_to_private_dns_zones.standard.secured`

Optional:

- `service_endpoints` (List of String) (Optional) The list of Service endpoints to associate with the subnet.


<a id="nestedatt--csp_configuration--azure--subscriptions--management--vnet--vnet_link_to_private_dns_zones--standard--secured"></a>
### Nested Schema for `csp_configuration.azure.subscriptions.management.vnet.vnet_link_to_private_dns_zones.standard.secured`

Optional:

- `delegation` (Attributes) (Optional) Provides details to deleted the subnet to a supported Azure service. (see [below for nested schema](#nestedatt--csp_configuration--azure--subscriptions--management--vnet--vnet_link_to_private_dns_zones--standard--secured--delegation))
- `service_endpoints` (List of String) (Optional) The list of Service endpoints to associate with the subnet.

<a id="nestedatt--csp_configuration--azure--subscriptions--management--vnet--vnet_link_to_private_dns_zones--standard--secured--delegation"></a>
### Nested Schema for `csp_configuration.azure.subscriptions.management.vnet.vnet_link_to_private_dns_zones.standard.secured.delegation`

Required:

- `name` (String) (Required) A name for this delegation.
- `service` (String) (Required) The name of service to delegate to.

Optional:

- `actions` (List of String) (Optional) A list of Actions which should be delegated. This list is specific to the service to delegate to.








<a id="nestedatt--csp_configuration--azure--budgets"></a>
### Nested Schema for `csp_configuration.azure.budgets`

Optional:

- `landingzone_nonprod` (Attributes List) (Optional) Configured budgets for landingzone-nonprod management group. (see [below for nested schema](#nestedatt--csp_configuration--azure--budgets--landingzone_nonprod))
- `landingzone_prod` (Attributes List) (Optional) Configured budgets for landingzone-prod management group. (see [below for nested schema](#nestedatt--csp_configuration--azure--budgets--landingzone_prod))
- `platform` (Attributes List) (Optional) Configured budgets for platform management group. (see [below for nested schema](#nestedatt--csp_configuration--azure--budgets--platform))
- `root` (Attributes List) (Optional) Configured budgets for root management group. (see [below for nested schema](#nestedatt--csp_configuration--azure--budgets--root))

<a id="nestedatt--csp_configuration--azure--budgets--landingzone_nonprod"></a>
### Nested Schema for `csp_configuration.azure.budgets.root`

Required:

- `amount` (Number) (Required) The total amount of cost to track with the budget.
- `notifications` (Attributes List) (Required) One or more notification objects. (see [below for nested schema](#nestedatt--csp_configuration--azure--budgets--root--notifications))

Optional:

- `time_grain` (String) (Optional) The time covered by a budget. Tracking of the amount will be reset based on the time grain. Must be one of BillingAnnual, BillingMonth, BillingQuarter, Annually, Monthly and Quarterly. Defaults to Monthly. Changing this forces a new resource to be created.

<a id="nestedatt--csp_configuration--azure--budgets--root--notifications"></a>
### Nested Schema for `csp_configuration.azure.budgets.root.notifications`

Required:

- `contact_emails` (List of String) (Required) Specifies a list of email addresses to send the budget notification to when the threshold is exceeded.
- `threshold` (Number) (Required) Threshold value associated with a notification. Notification is sent when the cost exceeded the threshold. It is always percent and has to be between 0 and 1000.

Optional:

- `operator` (String) (Optional) The comparison operator for the notification. Must be one of EqualTo, GreaterThan, or GreaterThanOrEqualTo. Defaults to EqualTo.
- `threshold_type` (String) (Optional) The type of threshold for the notification. This determines whether the notification is triggered by forecasted costs or actual costs. The allowed values are Actual and Forecasted. Default is Actual. Changing this forces a new resource to be created.



<a id="nestedatt--csp_configuration--azure--budgets--landingzone_prod"></a>
### Nested Schema for `csp_configuration.azure.budgets.root`

Required:

- `amount` (Number) (Required) The total amount of cost to track with the budget.
- `notifications` (Attributes List) (Required) One or more notification objects. (see [below for nested schema](#nestedatt--csp_configuration--azure--budgets--root--notifications))

Optional:

- `time_grain` (String) (Optional) The time covered by a budget. Tracking of the amount will be reset based on the time grain. Must be one of BillingAnnual, BillingMonth, BillingQuarter, Annually, Monthly and Quarterly. Defaults to Monthly. Changing this forces a new resource to be created.

<a id="nestedatt--csp_configuration--azure--budgets--root--notifications"></a>
### Nested Schema for `csp_configuration.azure.budgets.root.notifications`

Required:

- `contact_emails` (List of String) (Required) Specifies a list of email addresses to send the budget notification to when the threshold is exceeded.
- `threshold` (Number) (Required) Threshold value associated with a notification. Notification is sent when the cost exceeded the threshold. It is always percent and has to be between 0 and 1000.

Optional:

- `operator` (String) (Optional) The comparison operator for the notification. Must be one of EqualTo, GreaterThan, or GreaterThanOrEqualTo. Defaults to EqualTo.
- `threshold_type` (String) (Optional) The type of threshold for the notification. This determines whether the notification is triggered by forecasted costs or actual costs. The allowed values are Actual and Forecasted. Default is Actual. Changing this forces a new resource to be created.



<a id="nestedatt--csp_configuration--azure--budgets--platform"></a>
### Nested Schema for `csp_configuration.azure.budgets.root`

Required:

- `amount` (Number) (Required) The total amount of cost to track with the budget.
- `notifications` (Attributes List) (Required) One or more notification objects. (see [below for nested schema](#nestedatt--csp_configuration--azure--budgets--root--notifications))

Optional:

- `time_grain` (String) (Optional) The time covered by a budget. Tracking of the amount will be reset based on the time grain. Must be one of BillingAnnual, BillingMonth, BillingQuarter, Annually, Monthly and Quarterly. Defaults to Monthly. Changing this forces a new resource to be created.

<a id="nestedatt--csp_configuration--azure--budgets--root--notifications"></a>
### Nested Schema for `csp_configuration.azure.budgets.root.notifications`

Required:

- `contact_emails` (List of String) (Required) Specifies a list of email addresses to send the budget notification to when the threshold is exceeded.
- `threshold` (Number) (Required) Threshold value associated with a notification. Notification is sent when the cost exceeded the threshold. It is always percent and has to be between 0 and 1000.

Optional:

- `operator` (String) (Optional) The comparison operator for the notification. Must be one of EqualTo, GreaterThan, or GreaterThanOrEqualTo. Defaults to EqualTo.
- `threshold_type` (String) (Optional) The type of threshold for the notification. This determines whether the notification is triggered by forecasted costs or actual costs. The allowed values are Actual and Forecasted. Default is Actual. Changing this forces a new resource to be created.



<a id="nestedatt--csp_configuration--azure--budgets--root"></a>
### Nested Schema for `csp_configuration.azure.budgets.root`

Required:

- `amount` (Number) (Required) The total amount of cost to track with the budget.
- `notifications` (Attributes List) (Required) One or more notification objects. (see [below for nested schema](#nestedatt--csp_configuration--azure--budgets--root--notifications))

Optional:

- `time_grain` (String) (Optional) The time covered by a budget. Tracking of the amount will be reset based on the time grain. Must be one of BillingAnnual, BillingMonth, BillingQuarter, Annually, Monthly and Quarterly. Defaults to Monthly. Changing this forces a new resource to be created.

<a id="nestedatt--csp_configuration--azure--budgets--root--notifications"></a>
### Nested Schema for `csp_configuration.azure.budgets.root.notifications`

Required:

- `contact_emails` (List of String) (Required) Specifies a list of email addresses to send the budget notification to when the threshold is exceeded.
- `threshold` (Number) (Required) Threshold value associated with a notification. Notification is sent when the cost exceeded the threshold. It is always percent and has to be between 0 and 1000.

Optional:

- `operator` (String) (Optional) The comparison operator for the notification. Must be one of EqualTo, GreaterThan, or GreaterThanOrEqualTo. Defaults to EqualTo.
- `threshold_type` (String) (Optional) The type of threshold for the notification. This determines whether the notification is triggered by forecasted costs or actual costs. The allowed values are Actual and Forecasted. Default is Actual. Changing this forces a new resource to be created.





<a id="nestedatt--csp_configuration--gcp"></a>
### Nested Schema for `csp_configuration.gcp`

Required:

- `abbreviation` (String) (Required) This abbreviation will be used to uniquily identify resources created. Only applies to resources that require Azure global uniqueness and to Management Groups.



<a id="nestedatt--csp_credentials"></a>
### Nested Schema for `csp_credentials`

Optional:

- `aws` (Attributes) (Optional) It contains tenancy providers' credentials. (see [below for nested schema](#nestedatt--csp_credentials--aws))
- `azure` (Attributes) (Optional) It contains tenancy providers' credentials. (see [below for nested schema](#nestedatt--csp_credentials--azure))
- `gcp` (Attributes) (Optional) It contains tenancy providers' credentials. (see [below for nested schema](#nestedatt--csp_credentials--gcp))

<a id="nestedatt--csp_credentials--aws"></a>
### Nested Schema for `csp_credentials.aws`

Required:

- `provider` (Attributes) (Required) Provides service principal settings for using Azure AD terraform provider to configure resources in the target Azure AD tenant. Appropriate permissions are required for service principal. (see [below for nested schema](#nestedatt--csp_credentials--aws--provider))

Optional:

- `azuread` (Attributes) (Optional) Provides service principal settings for using Azure AD terraform provider to configure Azure AD as IdP for SSO with AWS Console. Appropriate permissions are required for service principal. (see [below for nested schema](#nestedatt--csp_credentials--aws--azuread))

<a id="nestedatt--csp_credentials--aws--provider"></a>
### Nested Schema for `csp_credentials.aws.provider`

Required:

- `access_key` (String, Sensitive) (Required) Target AWS Management Account service principal access key.
- `secret_key` (String, Sensitive) (Required) Target AWS Management Account service principal secret key.
- `service_principal_first_name` (String) (Required) First Name of the service principal.
- `service_principal_last_name` (String) (Required) First Last of the service principal.
- `service_principal_user_name` (String) (Required) User name of the service principal. MUST be in email format. To use automatic provisioning, this principal must to be in AWS SSO.

Optional:

- `scim_provisioning` (Attributes) (Optional) Provides the AWS Identity Centre SCIM details. (see [below for nested schema](#nestedatt--csp_credentials--aws--provider--scim_provisioning))

<a id="nestedatt--csp_credentials--aws--provider--scim_provisioning"></a>
### Nested Schema for `csp_credentials.aws.provider.scim_provisioning`

Required:

- `endpoint` (String) (Required) AWS Identity Centre SCIM Endpoint.
- `token` (String, Sensitive) (Required) AWS Identity Centre SCIM Token.



<a id="nestedatt--csp_credentials--aws--azuread"></a>
### Nested Schema for `csp_credentials.aws.azuread`

Required:

- `client_id` (String, Sensitive) (Required) Service Principal client ID configured in the target Azure AD tenant.
- `client_secret` (String, Sensitive) (Required) Service Principal client secret configured in the target Azure AD tenant.
- `tenant_id` (String, Sensitive) (Required) Target Azure AD tenant ID.



<a id="nestedatt--csp_credentials--azure"></a>
### Nested Schema for `csp_credentials.azure`

Required:

- `azuread` (Attributes) (Required) Provides service principal settings for using Azure AD terraform provider to configure resources in the target Azure AD tenant. Appropriate permissions are required for service principal. (see [below for nested schema](#nestedatt--csp_credentials--azure--azuread))
- `provider` (Attributes) (Required) Provides service principal settings for using Azure RM terraform provider to configure resources in the target Azure tenant. Appropriate permissions are required for service principal. (see [below for nested schema](#nestedatt--csp_credentials--azure--provider))

<a id="nestedatt--csp_credentials--azure--azuread"></a>
### Nested Schema for `csp_credentials.azure.azuread`

Required:

- `client_id` (String, Sensitive) (Required) Service Principal client ID configured in the target Azure AD tenant.
- `client_secret` (String, Sensitive) (Required) Service Principal client secret configured in the target Azure AD tenant.
- `tenant_id` (String, Sensitive) (Required) Target Azure AD tenant ID.


<a id="nestedatt--csp_credentials--azure--provider"></a>
### Nested Schema for `csp_credentials.azure.provider`

Required:

- `client_id` (String, Sensitive) (Required) Service Principal client ID configured in the target Azure tenant.
- `client_secret` (String, Sensitive) (Required) Service Principal client secret configured in the target Azure tenant.
- `subscription_id` (String, Sensitive) (Required) Target Azure Subscription ID.
- `tenant_id` (String, Sensitive) (Required) Target Azure tenant ID.



<a id="nestedatt--csp_credentials--gcp"></a>
### Nested Schema for `csp_credentials.gcp`

Required:

- `provider` (Attributes) (Required) Provides service principal settings for using Azure AD terraform provider to configure resources in the target Azure AD tenant. Appropriate permissions are required for service principal. (see [below for nested schema](#nestedatt--csp_credentials--gcp--provider))

<a id="nestedatt--csp_credentials--gcp--provider"></a>
### Nested Schema for `csp_credentials.gcp.provider`

Optional:

- `credentials` (String) (Optional) Either the path to or the contents of a service account key file in JSON format.

## Import

Import is supported using the following syntax:

```terraform
$ terraform import volocloud_tenancy.example <resource ID>
```
**NOTE:** The <resource ID> format is: "account_id:tenancy_id"
