---
description: |-
  Tenancy resource configuration main schema.
hide: toc
page_title: "volocloud_tenancy_azure Resource"
subcategory: ""
---

# volocloud_tenancy_azure

Tenancy resource configuration main schema.

## Example Usage

```terraform
# Example using Azure Existing Billing account of type MPA
resource "volocloud_tenancy_azure" "example" {
  account_id = volocloud_account.example.account_id
  configuration = {
    abbreviation = "expl"
    assume_identity = {
      tenant_id = "00000000-0000-0000-0000-000000000000"
    }
    billing = {
      account_type = "mpa"
      existing = {
        connectivity_subscription_id = "00000000-0000-0000-0000-000000000000"
        identity_subscription_id     = "00000000-0000-0000-0000-000000000000"
        management_subscription_id   = "00000000-0000-0000-0000-000000000000"
        security_subscription_id     = "00000000-0000-0000-0000-000000000000"
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
    regions = {
      home = {
        primary = {
          location = "australiaeast"
          network = {
            enabled = true
          }
          region = "auee"
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
      security = {
        abbreviation = "sec"
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
    }
    tags = {}
  }
  credentials = {
    client_id       = "00000000-0000-0000-0000-000000000000"
    client_secret   = "client_secret"
    subscription_id = "00000000-0000-0000-0000-000000000000"
    tenant_id       = "00000000-0000-0000-0000-000000000000"
  }
  name = "example"
}
```

<!-- schema generated by tfplugindocs -->
## Schema

### Required

- `account_id` (String) Volocloud Account ID associated with this account.
- `configuration` (Attributes) Provides configuration required to setup the Tenancy. (see [below for nested schema](#nestedatt--configuration))
- `credentials` (Attributes) Provides credentials required to setup the Tenancy. (see [below for nested schema](#nestedatt--credentials))
- `name` (String) Volocloud tenancy Name.

### Optional

- `trigger_update` (String) This attribute provides a mechanism to trigger an update on the tenancy resouce when there is no change to the other attributes.

### Read-Only

- `id` (String) ID of the resource computed from the account_id and tenancy_id separated by : .
- `provider_version` (String) The provider version which is used by this resource. It gets automatically updated whent he provider version is changed. It triggers an update on the tenancy resource.
- `resources` (Map of String) These are all the resources created in the tenancy.
- `tenancy_id` (String) Volocloud Tenancy ID.

<a id="nestedatt--configuration"></a>
### Nested Schema for `configuration`

Required:

- `abbreviation` (String) This abbreviation will be used to uniquily identify resources created. Only applies to resources that require Azure global uniqueness and to Management Groups.
- `assume_identity` (Attributes) Azure Tenant details for Volocloud bootstrap identity to be assumed. (see [below for nested schema](#nestedatt--configuration--assume_identity))
- `billing` (Attributes) Provides the details required for Microsoft Azure billing. Must provide only one of ea, existing, mca, mpa attributes. (see [below for nested schema](#nestedatt--configuration--billing))
- `dns_domain` (String) DNS domain associated with this tenancy.
- `regions` (Attributes) Defines which regions to deploy into. (see [below for nested schema](#nestedatt--configuration--regions))
- `subscriptions` (Attributes) Azure Core Subscriptions: connectivity, identity and management configuration. (see [below for nested schema](#nestedatt--configuration--subscriptions))

Optional:

- `budgets` (Attributes) Provides a nested List of nested budget object to associate with a Management Group. (see [below for nested schema](#nestedatt--configuration--budgets))
- `environments` (List of String) List of environments to be deployed part of the tenancy. Possible value are `dev`, `prod`, `qa` or `test`. Defaults to `[dev, prod, test]`
- `tags` (Map of String) Key-value map of resource tags for all the tenancy resources.

<a id="nestedatt--configuration--assume_identity"></a>
### Nested Schema for `configuration.assume_identity`

Required:

- `tenant_id` (String) The Azure Tenant ID where Volo bootstrap identity was created from the Azure ARM Template provided by the volocloud provider account resource.


<a id="nestedatt--configuration--billing"></a>
### Nested Schema for `configuration.billing`

Required:

- `account_type` (String) Microsoft Azure Billing Account type. Possible values are `ea`, `mca` or `mpa`.

Optional:

- `ea` (Attributes) Provides required billing information to create subscriptions for a Microsoft Enterprise Agreement billing account. Conflicts with existing, mca, mpa. (see [below for nested schema](#nestedatt--configuration--billing--ea))
- `existing` (Attributes) Provides existing tenancy core subscription ids. Conflicts with ea, mca, mpa. (see [below for nested schema](#nestedatt--configuration--billing--existing))
- `mca` (Attributes) Provides required billing information to create subscriptions for an Microsoft Customer Agreement billing account. Conflicts with existing, ea, mpa. (see [below for nested schema](#nestedatt--configuration--billing--mca))
- `mpa` (Attributes) All the CSP Partners that we support to create subscriptions programatically. Conflicts with ea, existing, mca attributes. (see [below for nested schema](#nestedatt--configuration--billing--mpa))

<a id="nestedatt--configuration--billing--ea"></a>
### Nested Schema for `configuration.billing.ea`

Required:

- `account_id` (String) Microsoft Enterprise Agreement billing account id.
- `enrollment_id` (String) Microsoft Enterprise Agreement billing enrollment id.


<a id="nestedatt--configuration--billing--existing"></a>
### Nested Schema for `configuration.billing.existing`

Required:

- `connectivity_subscription_id` (String) Existing subscription id to be used for connectivity.
- `identity_subscription_id` (String) Existing subscription id to be used for identity.
- `management_subscription_id` (String) Existing subscription id to be used for management.
- `security_subscription_id` (String) Existing subscription id to be used for security.


<a id="nestedatt--configuration--billing--mca"></a>
### Nested Schema for `configuration.billing.mca`

Required:

- `account_id` (String) Microsoft Customer Agreement billing account id.
- `invoice_id` (String) Microsoft Customer Agreement billing invoice id.
- `profile_id` (String) Microsoft Customer Agreement billing profile id.


<a id="nestedatt--configuration--billing--mpa"></a>
### Nested Schema for `configuration.billing.mpa`

Optional:

- `rhipe` (Attributes) (see [below for nested schema](#nestedatt--configuration--billing--mpa--rhipe))

<a id="nestedatt--configuration--billing--mpa--rhipe"></a>
### Nested Schema for `configuration.billing.mpa.rhipe`

Optional:

- `description` (String) Rhipe Description.




<a id="nestedatt--configuration--regions"></a>
### Nested Schema for `configuration.regions`

Required:

- `home` (Attributes) Home geography containing a pair of primary/secondary regions. (see [below for nested schema](#nestedatt--configuration--regions--home))

Optional:

- `other` (Attributes List) A list of Non-Home geographies containing a pair of primary/secondary regions in each geography. (see [below for nested schema](#nestedatt--configuration--regions--other))

<a id="nestedatt--configuration--regions--home"></a>
### Nested Schema for `configuration.regions.home`

Required:

- `primary` (Attributes) Primary Aws Region details. (see [below for nested schema](#nestedatt--configuration--regions--home--primary))

Optional:

- `secondary` (Attributes) Secondary Aws Region details. (see [below for nested schema](#nestedatt--configuration--regions--home--secondary))

<a id="nestedatt--configuration--regions--home--primary"></a>
### Nested Schema for `configuration.regions.home.primary`

Required:

- `location` (String) The Azure location of the region. Possible values are `[australiacentral australiacentral2 australiaeast australiasoutheast austriaeast brazilsouth brazilsoutheast canadacentral canadaeast centralindia centralus chilecentral chinaeast chinaeast2 chinanorth chinanorth2 eastasia eastus eastus2 francecentral francesouth germanynorth germanywestcentral indonesiacentral israelcentral italynorth japaneast japanwest koreacentral koreasouth malaysiawest mexicocentral newzealandnorth northcentralus northeurope norwayeast norwaywest polandcentral qatarcentral southafricanorth southafricawest southcentralus southeastasia southindia spaincentral swedencentral switzerlandnorth switzerlandwest uaecentral uaenorth uksouth ukwest usdodcentral usdodeast usgovarizona usgovtexas usgovvirginia westcentralus westeurope westindia westus westus2 westus3]`.
- `network` (Attributes) This information is used to deploy a network on top of the landing zone. A lot of other services depend on this. (see [below for nested schema](#nestedatt--configuration--regions--home--primary--network))
- `region` (String) The Azure region code of the location. Possible values are `[aecc aenn apee apse atee auc2 aucc auee ause brse brss cacc caee chnn chww clee cne2 cnee cnn2 cnnn decw denn escc eunn euww frcc frss gbss gbww idcc ilcc incc inss inww itnn jpee jpww krcc krss mxcc myww noee noww nznn plcc qacc secc uscc uscn uscs uscw usdc usde use2 usee usgc usge usgw usw2 usw3 usww zann zaww]`.

<a id="nestedatt--configuration--regions--home--primary--network"></a>
### Nested Schema for `configuration.regions.home.primary.network`

Required:

- `enabled` (Boolean) If enabled, it will deploy a network on top of the landing zone.

Optional:

- `ip_schema` (Attributes) (see [below for nested schema](#nestedatt--configuration--regions--home--primary--network--ip_schema))

<a id="nestedatt--configuration--regions--home--primary--network--ip_schema"></a>
### Nested Schema for `configuration.regions.home.primary.network.ip_schema`

Optional:

- `address` (String) The base IP Network for the entire region (e.g. x.x.x.x). It will be used to perform IPAM for the tenancy and it's tenancy accounts. CANNOT be changed after creation without destroying everything running on top of the network. Defaults to `172.16.0.0`.
- `environments` (Attributes) The Network CIDR configuration for environments. (see [below for nested schema](#nestedatt--configuration--regions--home--primary--network--ip_schema--environments))
- `mask` (Number) The base IP Network Mask for the entire region (e.g. `16`). It will be used to perform IPAM for the tenancy and it's tenancy accounts. It MUST be between `8` and `18`. CANNOT be changed after creation without destroying everything running on top of the network. Defaults to `16`

<a id="nestedatt--configuration--regions--home--primary--network--ip_schema--environments"></a>
### Nested Schema for `configuration.regions.home.primary.network.ip_schema.environments`

Optional:

- `core` (Attributes) The IP CIDR for environment. (see [below for nested schema](#nestedatt--configuration--regions--home--primary--network--ip_schema--environments--core))
- `dev` (Attributes) The IP CIDR for environment. (see [below for nested schema](#nestedatt--configuration--regions--home--primary--network--ip_schema--environments--dev))
- `prod` (Attributes) The IP CIDR for environment. (see [below for nested schema](#nestedatt--configuration--regions--home--primary--network--ip_schema--environments--prod))
- `qa` (Attributes) The IP CIDR for environment. (see [below for nested schema](#nestedatt--configuration--regions--home--primary--network--ip_schema--environments--qa))
- `test` (Attributes) The IP CIDR for environment. (see [below for nested schema](#nestedatt--configuration--regions--home--primary--network--ip_schema--environments--test))

<a id="nestedatt--configuration--regions--home--primary--network--ip_schema--environments--core"></a>
### Nested Schema for `configuration.regions.home.primary.network.ip_schema.environments.core`

Optional:

- `address` (String) The base IP Network for the environment. CANNOT be changed after creation without destroying everything running on top of the network.
- `mask` (Number) The base IP Network Mask for the environment. It MUST be between `10` and `20`. CANNOT be changed after creation without destroying everything running on top of the network.


<a id="nestedatt--configuration--regions--home--primary--network--ip_schema--environments--dev"></a>
### Nested Schema for `configuration.regions.home.primary.network.ip_schema.environments.dev`

Optional:

- `address` (String) The base IP Network for the environment. CANNOT be changed after creation without destroying everything running on top of the network.
- `mask` (Number) The base IP Network Mask for the environment. It MUST be between `10` and `20`. CANNOT be changed after creation without destroying everything running on top of the network.


<a id="nestedatt--configuration--regions--home--primary--network--ip_schema--environments--prod"></a>
### Nested Schema for `configuration.regions.home.primary.network.ip_schema.environments.prod`

Optional:

- `address` (String) The base IP Network for the environment. CANNOT be changed after creation without destroying everything running on top of the network.
- `mask` (Number) The base IP Network Mask for the environment. It MUST be between `10` and `20`. CANNOT be changed after creation without destroying everything running on top of the network.


<a id="nestedatt--configuration--regions--home--primary--network--ip_schema--environments--qa"></a>
### Nested Schema for `configuration.regions.home.primary.network.ip_schema.environments.qa`

Optional:

- `address` (String) The base IP Network for the environment. CANNOT be changed after creation without destroying everything running on top of the network.
- `mask` (Number) The base IP Network Mask for the environment. It MUST be between `10` and `20`. CANNOT be changed after creation without destroying everything running on top of the network.


<a id="nestedatt--configuration--regions--home--primary--network--ip_schema--environments--test"></a>
### Nested Schema for `configuration.regions.home.primary.network.ip_schema.environments.test`

Optional:

- `address` (String) The base IP Network for the environment. CANNOT be changed after creation without destroying everything running on top of the network.
- `mask` (Number) The base IP Network Mask for the environment. It MUST be between `10` and `20`. CANNOT be changed after creation without destroying everything running on top of the network.






<a id="nestedatt--configuration--regions--home--secondary"></a>
### Nested Schema for `configuration.regions.home.secondary`

Required:

- `location` (String) The Azure location of the region. Possible values are `[australiacentral australiacentral2 australiaeast australiasoutheast austriaeast brazilsouth brazilsoutheast canadacentral canadaeast centralindia centralus chilecentral chinaeast chinaeast2 chinanorth chinanorth2 eastasia eastus eastus2 francecentral francesouth germanynorth germanywestcentral indonesiacentral israelcentral italynorth japaneast japanwest koreacentral koreasouth malaysiawest mexicocentral newzealandnorth northcentralus northeurope norwayeast norwaywest polandcentral qatarcentral southafricanorth southafricawest southcentralus southeastasia southindia spaincentral swedencentral switzerlandnorth switzerlandwest uaecentral uaenorth uksouth ukwest usdodcentral usdodeast usgovarizona usgovtexas usgovvirginia westcentralus westeurope westindia westus westus2 westus3]`.
- `network` (Attributes) This information is used to deploy a network on top of the landing zone. A lot of other services depend on this. (see [below for nested schema](#nestedatt--configuration--regions--home--secondary--network))
- `region` (String) The Azure region code of the location. Possible values are `[aecc aenn apee apse atee auc2 aucc auee ause brse brss cacc caee chnn chww clee cne2 cnee cnn2 cnnn decw denn escc eunn euww frcc frss gbss gbww idcc ilcc incc inss inww itnn jpee jpww krcc krss mxcc myww noee noww nznn plcc qacc secc uscc uscn uscs uscw usdc usde use2 usee usgc usge usgw usw2 usw3 usww zann zaww]`.

<a id="nestedatt--configuration--regions--home--secondary--network"></a>
### Nested Schema for `configuration.regions.home.secondary.network`

Required:

- `enabled` (Boolean) If enabled, it will deploy a network on top of the landing zone.

Optional:

- `ip_schema` (Attributes) (see [below for nested schema](#nestedatt--configuration--regions--home--secondary--network--ip_schema))

<a id="nestedatt--configuration--regions--home--secondary--network--ip_schema"></a>
### Nested Schema for `configuration.regions.home.secondary.network.ip_schema`

Optional:

- `address` (String) The base IP Network for the entire region (e.g. x.x.x.x). It will be used to perform IPAM for the tenancy and it's tenancy accounts. CANNOT be changed after creation without destroying everything running on top of the network. Defaults to `172.16.0.0`.
- `environments` (Attributes) The Network CIDR configuration for environments. (see [below for nested schema](#nestedatt--configuration--regions--home--secondary--network--ip_schema--environments))
- `mask` (Number) The base IP Network Mask for the entire region (e.g. `16`). It will be used to perform IPAM for the tenancy and it's tenancy accounts. It MUST be between `8` and `18`. CANNOT be changed after creation without destroying everything running on top of the network. Defaults to `16`

<a id="nestedatt--configuration--regions--home--secondary--network--ip_schema--environments"></a>
### Nested Schema for `configuration.regions.home.secondary.network.ip_schema.environments`

Optional:

- `core` (Attributes) The IP CIDR for environment. (see [below for nested schema](#nestedatt--configuration--regions--home--secondary--network--ip_schema--environments--core))
- `dev` (Attributes) The IP CIDR for environment. (see [below for nested schema](#nestedatt--configuration--regions--home--secondary--network--ip_schema--environments--dev))
- `prod` (Attributes) The IP CIDR for environment. (see [below for nested schema](#nestedatt--configuration--regions--home--secondary--network--ip_schema--environments--prod))
- `qa` (Attributes) The IP CIDR for environment. (see [below for nested schema](#nestedatt--configuration--regions--home--secondary--network--ip_schema--environments--qa))
- `test` (Attributes) The IP CIDR for environment. (see [below for nested schema](#nestedatt--configuration--regions--home--secondary--network--ip_schema--environments--test))

<a id="nestedatt--configuration--regions--home--secondary--network--ip_schema--environments--core"></a>
### Nested Schema for `configuration.regions.home.secondary.network.ip_schema.environments.core`

Optional:

- `address` (String) The base IP Network for the environment. CANNOT be changed after creation without destroying everything running on top of the network.
- `mask` (Number) The base IP Network Mask for the environment. It MUST be between `10` and `20`. CANNOT be changed after creation without destroying everything running on top of the network.


<a id="nestedatt--configuration--regions--home--secondary--network--ip_schema--environments--dev"></a>
### Nested Schema for `configuration.regions.home.secondary.network.ip_schema.environments.dev`

Optional:

- `address` (String) The base IP Network for the environment. CANNOT be changed after creation without destroying everything running on top of the network.
- `mask` (Number) The base IP Network Mask for the environment. It MUST be between `10` and `20`. CANNOT be changed after creation without destroying everything running on top of the network.


<a id="nestedatt--configuration--regions--home--secondary--network--ip_schema--environments--prod"></a>
### Nested Schema for `configuration.regions.home.secondary.network.ip_schema.environments.prod`

Optional:

- `address` (String) The base IP Network for the environment. CANNOT be changed after creation without destroying everything running on top of the network.
- `mask` (Number) The base IP Network Mask for the environment. It MUST be between `10` and `20`. CANNOT be changed after creation without destroying everything running on top of the network.


<a id="nestedatt--configuration--regions--home--secondary--network--ip_schema--environments--qa"></a>
### Nested Schema for `configuration.regions.home.secondary.network.ip_schema.environments.qa`

Optional:

- `address` (String) The base IP Network for the environment. CANNOT be changed after creation without destroying everything running on top of the network.
- `mask` (Number) The base IP Network Mask for the environment. It MUST be between `10` and `20`. CANNOT be changed after creation without destroying everything running on top of the network.


<a id="nestedatt--configuration--regions--home--secondary--network--ip_schema--environments--test"></a>
### Nested Schema for `configuration.regions.home.secondary.network.ip_schema.environments.test`

Optional:

- `address` (String) The base IP Network for the environment. CANNOT be changed after creation without destroying everything running on top of the network.
- `mask` (Number) The base IP Network Mask for the environment. It MUST be between `10` and `20`. CANNOT be changed after creation without destroying everything running on top of the network.







<a id="nestedatt--configuration--regions--other"></a>
### Nested Schema for `configuration.regions.other`

Required:

- `primary` (Attributes) Primary Aws Region details. (see [below for nested schema](#nestedatt--configuration--regions--other--primary))

Optional:

- `secondary` (Attributes) Secondary Aws Region details. (see [below for nested schema](#nestedatt--configuration--regions--other--secondary))

<a id="nestedatt--configuration--regions--other--primary"></a>
### Nested Schema for `configuration.regions.other.primary`

Required:

- `location` (String) The Azure location of the region. Possible values are `[australiacentral australiacentral2 australiaeast australiasoutheast austriaeast brazilsouth brazilsoutheast canadacentral canadaeast centralindia centralus chilecentral chinaeast chinaeast2 chinanorth chinanorth2 eastasia eastus eastus2 francecentral francesouth germanynorth germanywestcentral indonesiacentral israelcentral italynorth japaneast japanwest koreacentral koreasouth malaysiawest mexicocentral newzealandnorth northcentralus northeurope norwayeast norwaywest polandcentral qatarcentral southafricanorth southafricawest southcentralus southeastasia southindia spaincentral swedencentral switzerlandnorth switzerlandwest uaecentral uaenorth uksouth ukwest usdodcentral usdodeast usgovarizona usgovtexas usgovvirginia westcentralus westeurope westindia westus westus2 westus3]`.
- `network` (Attributes) This information is used to deploy a network on top of the landing zone. A lot of other services depend on this. (see [below for nested schema](#nestedatt--configuration--regions--other--primary--network))
- `region` (String) The Azure region code of the location. Possible values are `[aecc aenn apee apse atee auc2 aucc auee ause brse brss cacc caee chnn chww clee cne2 cnee cnn2 cnnn decw denn escc eunn euww frcc frss gbss gbww idcc ilcc incc inss inww itnn jpee jpww krcc krss mxcc myww noee noww nznn plcc qacc secc uscc uscn uscs uscw usdc usde use2 usee usgc usge usgw usw2 usw3 usww zann zaww]`.

<a id="nestedatt--configuration--regions--other--primary--network"></a>
### Nested Schema for `configuration.regions.other.primary.network`

Required:

- `enabled` (Boolean) If enabled, it will deploy a network on top of the landing zone.

Optional:

- `ip_schema` (Attributes) (see [below for nested schema](#nestedatt--configuration--regions--other--primary--network--ip_schema))

<a id="nestedatt--configuration--regions--other--primary--network--ip_schema"></a>
### Nested Schema for `configuration.regions.other.primary.network.ip_schema`

Optional:

- `address` (String) The base IP Network for the entire region (e.g. x.x.x.x). It will be used to perform IPAM for the tenancy and it's tenancy accounts. CANNOT be changed after creation without destroying everything running on top of the network. Defaults to `172.16.0.0`.
- `environments` (Attributes) The Network CIDR configuration for environments. (see [below for nested schema](#nestedatt--configuration--regions--other--primary--network--ip_schema--environments))
- `mask` (Number) The base IP Network Mask for the entire region (e.g. `16`). It will be used to perform IPAM for the tenancy and it's tenancy accounts. It MUST be between `8` and `18`. CANNOT be changed after creation without destroying everything running on top of the network. Defaults to `16`

<a id="nestedatt--configuration--regions--other--primary--network--ip_schema--environments"></a>
### Nested Schema for `configuration.regions.other.primary.network.ip_schema.environments`

Optional:

- `core` (Attributes) The IP CIDR for environment. (see [below for nested schema](#nestedatt--configuration--regions--other--primary--network--ip_schema--environments--core))
- `dev` (Attributes) The IP CIDR for environment. (see [below for nested schema](#nestedatt--configuration--regions--other--primary--network--ip_schema--environments--dev))
- `prod` (Attributes) The IP CIDR for environment. (see [below for nested schema](#nestedatt--configuration--regions--other--primary--network--ip_schema--environments--prod))
- `qa` (Attributes) The IP CIDR for environment. (see [below for nested schema](#nestedatt--configuration--regions--other--primary--network--ip_schema--environments--qa))
- `test` (Attributes) The IP CIDR for environment. (see [below for nested schema](#nestedatt--configuration--regions--other--primary--network--ip_schema--environments--test))

<a id="nestedatt--configuration--regions--other--primary--network--ip_schema--environments--core"></a>
### Nested Schema for `configuration.regions.other.primary.network.ip_schema.environments.core`

Optional:

- `address` (String) The base IP Network for the environment. CANNOT be changed after creation without destroying everything running on top of the network.
- `mask` (Number) The base IP Network Mask for the environment. It MUST be between `10` and `20`. CANNOT be changed after creation without destroying everything running on top of the network.


<a id="nestedatt--configuration--regions--other--primary--network--ip_schema--environments--dev"></a>
### Nested Schema for `configuration.regions.other.primary.network.ip_schema.environments.dev`

Optional:

- `address` (String) The base IP Network for the environment. CANNOT be changed after creation without destroying everything running on top of the network.
- `mask` (Number) The base IP Network Mask for the environment. It MUST be between `10` and `20`. CANNOT be changed after creation without destroying everything running on top of the network.


<a id="nestedatt--configuration--regions--other--primary--network--ip_schema--environments--prod"></a>
### Nested Schema for `configuration.regions.other.primary.network.ip_schema.environments.prod`

Optional:

- `address` (String) The base IP Network for the environment. CANNOT be changed after creation without destroying everything running on top of the network.
- `mask` (Number) The base IP Network Mask for the environment. It MUST be between `10` and `20`. CANNOT be changed after creation without destroying everything running on top of the network.


<a id="nestedatt--configuration--regions--other--primary--network--ip_schema--environments--qa"></a>
### Nested Schema for `configuration.regions.other.primary.network.ip_schema.environments.qa`

Optional:

- `address` (String) The base IP Network for the environment. CANNOT be changed after creation without destroying everything running on top of the network.
- `mask` (Number) The base IP Network Mask for the environment. It MUST be between `10` and `20`. CANNOT be changed after creation without destroying everything running on top of the network.


<a id="nestedatt--configuration--regions--other--primary--network--ip_schema--environments--test"></a>
### Nested Schema for `configuration.regions.other.primary.network.ip_schema.environments.test`

Optional:

- `address` (String) The base IP Network for the environment. CANNOT be changed after creation without destroying everything running on top of the network.
- `mask` (Number) The base IP Network Mask for the environment. It MUST be between `10` and `20`. CANNOT be changed after creation without destroying everything running on top of the network.






<a id="nestedatt--configuration--regions--other--secondary"></a>
### Nested Schema for `configuration.regions.other.secondary`

Required:

- `location` (String) The Azure location of the region. Possible values are `[australiacentral australiacentral2 australiaeast australiasoutheast austriaeast brazilsouth brazilsoutheast canadacentral canadaeast centralindia centralus chilecentral chinaeast chinaeast2 chinanorth chinanorth2 eastasia eastus eastus2 francecentral francesouth germanynorth germanywestcentral indonesiacentral israelcentral italynorth japaneast japanwest koreacentral koreasouth malaysiawest mexicocentral newzealandnorth northcentralus northeurope norwayeast norwaywest polandcentral qatarcentral southafricanorth southafricawest southcentralus southeastasia southindia spaincentral swedencentral switzerlandnorth switzerlandwest uaecentral uaenorth uksouth ukwest usdodcentral usdodeast usgovarizona usgovtexas usgovvirginia westcentralus westeurope westindia westus westus2 westus3]`.
- `network` (Attributes) This information is used to deploy a network on top of the landing zone. A lot of other services depend on this. (see [below for nested schema](#nestedatt--configuration--regions--other--secondary--network))
- `region` (String) The Azure region code of the location. Possible values are `[aecc aenn apee apse atee auc2 aucc auee ause brse brss cacc caee chnn chww clee cne2 cnee cnn2 cnnn decw denn escc eunn euww frcc frss gbss gbww idcc ilcc incc inss inww itnn jpee jpww krcc krss mxcc myww noee noww nznn plcc qacc secc uscc uscn uscs uscw usdc usde use2 usee usgc usge usgw usw2 usw3 usww zann zaww]`.

<a id="nestedatt--configuration--regions--other--secondary--network"></a>
### Nested Schema for `configuration.regions.other.secondary.network`

Required:

- `enabled` (Boolean) If enabled, it will deploy a network on top of the landing zone.

Optional:

- `ip_schema` (Attributes) (see [below for nested schema](#nestedatt--configuration--regions--other--secondary--network--ip_schema))

<a id="nestedatt--configuration--regions--other--secondary--network--ip_schema"></a>
### Nested Schema for `configuration.regions.other.secondary.network.ip_schema`

Optional:

- `address` (String) The base IP Network for the entire region (e.g. x.x.x.x). It will be used to perform IPAM for the tenancy and it's tenancy accounts. CANNOT be changed after creation without destroying everything running on top of the network. Defaults to `172.16.0.0`.
- `environments` (Attributes) The Network CIDR configuration for environments. (see [below for nested schema](#nestedatt--configuration--regions--other--secondary--network--ip_schema--environments))
- `mask` (Number) The base IP Network Mask for the entire region (e.g. `16`). It will be used to perform IPAM for the tenancy and it's tenancy accounts. It MUST be between `8` and `18`. CANNOT be changed after creation without destroying everything running on top of the network. Defaults to `16`

<a id="nestedatt--configuration--regions--other--secondary--network--ip_schema--environments"></a>
### Nested Schema for `configuration.regions.other.secondary.network.ip_schema.environments`

Optional:

- `core` (Attributes) The IP CIDR for environment. (see [below for nested schema](#nestedatt--configuration--regions--other--secondary--network--ip_schema--environments--core))
- `dev` (Attributes) The IP CIDR for environment. (see [below for nested schema](#nestedatt--configuration--regions--other--secondary--network--ip_schema--environments--dev))
- `prod` (Attributes) The IP CIDR for environment. (see [below for nested schema](#nestedatt--configuration--regions--other--secondary--network--ip_schema--environments--prod))
- `qa` (Attributes) The IP CIDR for environment. (see [below for nested schema](#nestedatt--configuration--regions--other--secondary--network--ip_schema--environments--qa))
- `test` (Attributes) The IP CIDR for environment. (see [below for nested schema](#nestedatt--configuration--regions--other--secondary--network--ip_schema--environments--test))

<a id="nestedatt--configuration--regions--other--secondary--network--ip_schema--environments--core"></a>
### Nested Schema for `configuration.regions.other.secondary.network.ip_schema.environments.core`

Optional:

- `address` (String) The base IP Network for the environment. CANNOT be changed after creation without destroying everything running on top of the network.
- `mask` (Number) The base IP Network Mask for the environment. It MUST be between `10` and `20`. CANNOT be changed after creation without destroying everything running on top of the network.


<a id="nestedatt--configuration--regions--other--secondary--network--ip_schema--environments--dev"></a>
### Nested Schema for `configuration.regions.other.secondary.network.ip_schema.environments.dev`

Optional:

- `address` (String) The base IP Network for the environment. CANNOT be changed after creation without destroying everything running on top of the network.
- `mask` (Number) The base IP Network Mask for the environment. It MUST be between `10` and `20`. CANNOT be changed after creation without destroying everything running on top of the network.


<a id="nestedatt--configuration--regions--other--secondary--network--ip_schema--environments--prod"></a>
### Nested Schema for `configuration.regions.other.secondary.network.ip_schema.environments.prod`

Optional:

- `address` (String) The base IP Network for the environment. CANNOT be changed after creation without destroying everything running on top of the network.
- `mask` (Number) The base IP Network Mask for the environment. It MUST be between `10` and `20`. CANNOT be changed after creation without destroying everything running on top of the network.


<a id="nestedatt--configuration--regions--other--secondary--network--ip_schema--environments--qa"></a>
### Nested Schema for `configuration.regions.other.secondary.network.ip_schema.environments.qa`

Optional:

- `address` (String) The base IP Network for the environment. CANNOT be changed after creation without destroying everything running on top of the network.
- `mask` (Number) The base IP Network Mask for the environment. It MUST be between `10` and `20`. CANNOT be changed after creation without destroying everything running on top of the network.


<a id="nestedatt--configuration--regions--other--secondary--network--ip_schema--environments--test"></a>
### Nested Schema for `configuration.regions.other.secondary.network.ip_schema.environments.test`

Optional:

- `address` (String) The base IP Network for the environment. CANNOT be changed after creation without destroying everything running on top of the network.
- `mask` (Number) The base IP Network Mask for the environment. It MUST be between `10` and `20`. CANNOT be changed after creation without destroying everything running on top of the network.








<a id="nestedatt--configuration--subscriptions"></a>
### Nested Schema for `configuration.subscriptions`

Required:

- `connectivity` (Attributes) Provides details for configuring connectivity resources. (see [below for nested schema](#nestedatt--configuration--subscriptions--connectivity))
- `identity` (Attributes) Provides details for configuring identity resources. (see [below for nested schema](#nestedatt--configuration--subscriptions--identity))
- `management` (Attributes) Provides details for configuring management resources. (see [below for nested schema](#nestedatt--configuration--subscriptions--management))
- `security` (Attributes) Provides details for configuring identity resources. (see [below for nested schema](#nestedatt--configuration--subscriptions--security))

<a id="nestedatt--configuration--subscriptions--connectivity"></a>
### Nested Schema for `configuration.subscriptions.connectivity`

Required:

- `abbreviation` (String) This abbreviation will be used to uniquily identify resources created in this subscription. Only applies to resources that require Azure global uniqueness.

Optional:

- `azure_bastion` (Attributes) Azure Bastion configuration details. (see [below for nested schema](#nestedatt--configuration--subscriptions--connectivity--azure_bastion))
- `backups` (Attributes) Configuration settings for backups in this subscription. Defaults to {"recovery_services_vault":{"backup_policies":{"file_share":[{"frequency":{"daily":{"time":"23:00"},"hourly":<null>},"name":"daily","retention":{"daily":{"count":33},"monthly":<null>,"weekly":<null>,"yearly":<null>},"timezone":"UTC"},{"frequency":{"daily":{"time":"23:00"},"hourly":<null>},"name":"monthly","retention":{"daily":{"count":33},"monthly":{"count":13,"days":<null>,"include_last_days":<null>,"weekdays":["Sunday"],"weeks":["Last"]},"weekly":{"count":13,"weekdays":["Saturday"]},"yearly":<null>},"timezone":"UTC"},{"frequency":{"daily":{"time":"23:00"},"hourly":<null>},"name":"weekly","retention":{"daily":{"count":33},"monthly":<null>,"weekly":{"count":13,"weekdays":["Saturday"]},"yearly":<null>},"timezone":"UTC"},{"frequency":{"daily":{"time":"23:00"},"hourly":<null>},"name":"yearly","retention":{"daily":{"count":33},"monthly":{"count":13,"days":<null>,"include_last_days":<null>,"weekdays":["Sunday"],"weeks":["Last"]},"weekly":{"count":13,"weekdays":["Saturday"]},"yearly":{"count":7,"days":<null>,"include_last_days":<null>,"months":["January"],"weekdays":["Monday"],"weeks":["First"]}},"timezone":"UTC"}],"vm":[{"frequency":{"daily":{"time":"23:00"},"hourly":<null>,"weekly":<null>},"name":"daily","policy_type":{"v1":<null>,"v2":{"instant_restore_retention_days":7}},"retention":{"daily":{"count":33},"monthly":<null>,"weekly":<null>,"yearly":<null>},"tiering_policy":<null>,"timezone":"UTC"},{"frequency":{"daily":{"time":"23:00"},"hourly":<null>,"weekly":<null>},"name":"monthly","policy_type":{"v1":<null>,"v2":{"instant_restore_retention_days":7}},"retention":{"daily":{"count":33},"monthly":{"count":13,"days":<null>,"include_last_days":<null>,"weekdays":["Sunday"],"weeks":["Last"]},"weekly":{"count":5,"weekdays":["Saturday"]},"yearly":<null>},"tiering_policy":<null>,"timezone":"UTC"},{"frequency":{"daily":{"time":"23:00"},"hourly":<null>,"weekly":<null>},"name":"weekly","policy_type":{"v1":<null>,"v2":{"instant_restore_retention_days":7}},"retention":{"daily":{"count":33},"monthly":<null>,"weekly":{"count":5,"weekdays":["Saturday"]},"yearly":<null>},"tiering_policy":<null>,"timezone":"UTC"},{"frequency":{"daily":{"time":"23:00"},"hourly":<null>,"weekly":<null>},"name":"yearly","policy_type":{"v1":<null>,"v2":{"instant_restore_retention_days":7}},"retention":{"daily":{"count":33},"monthly":{"count":13,"days":<null>,"include_last_days":<null>,"weekdays":["Sunday"],"weeks":["Last"]},"weekly":{"count":5,"weekdays":["Saturday"]},"yearly":{"count":7,"days":<null>,"include_last_days":<null>,"months":["January"],"weekdays":["Monday"],"weeks":["First"]}},"tiering_policy":<null>,"timezone":"UTC"}]},"encryption":{"enabled":true,"infrastructure_encryption":false},"immutability":<null>,"monitoring":{"alerts_for_all_job_failures":true},"sku":"Standard","soft_delete":true,"storage_mode_type":"GeoRedundant","tags":<null>}} (see [below for nested schema](#nestedatt--configuration--subscriptions--connectivity--backups))
- `budgets` (Attributes List) Provides a list of budget objects. (see [below for nested schema](#nestedatt--configuration--subscriptions--connectivity--budgets))
- `ddos_protection_plan` (Attributes) Azure DDOS Protection Plan configuration. If not provides, DDOS Protection Plan will not be enabled. (see [below for nested schema](#nestedatt--configuration--subscriptions--connectivity--ddos_protection_plan))
- `dns_resolver` (Attributes) Azure Private DNS Resolver configuration. (see [below for nested schema](#nestedatt--configuration--subscriptions--connectivity--dns_resolver))
- `dns_zones` (Attributes) Azure DNS Zones for public and private DNS object. (see [below for nested schema](#nestedatt--configuration--subscriptions--connectivity--dns_zones))
- `hub_networks` (Attributes) Hub and Spoke setup. Conflicts with vwan_hub_networks. (see [below for nested schema](#nestedatt--configuration--subscriptions--connectivity--hub_networks))
- `keyvault` (Attributes) Azure KeyVault configuration details. (see [below for nested schema](#nestedatt--configuration--subscriptions--connectivity--keyvault))
- `resource_groups_lock` (Attributes) Configures Azure Delete Lock at Resource Groups level. (see [below for nested schema](#nestedatt--configuration--subscriptions--connectivity--resource_groups_lock))
- `vwan_hub_networks` (Attributes) VWAN setup. Conflicts with hub_networks. (see [below for nested schema](#nestedatt--configuration--subscriptions--connectivity--vwan_hub_networks))

<a id="nestedatt--configuration--subscriptions--connectivity--azure_bastion"></a>
### Nested Schema for `configuration.subscriptions.connectivity.azure_bastion`

Optional:

- `copy_paste` (Boolean) Is Copy/Paste feature enabled for the Bastion Host. Defaults to true.
- `enabled` (Boolean) Is Azure Bastion enabled? Defaults to true.
- `file_copy` (Boolean) Is File Copy feature enabled for the Bastion Host. Defaults to false.
- `sku` (String) The SKU of the Bastion Host. Accepted values are Basic and Standard. Defaults to Basic.
- `tunneling` (Boolean) Is Tunneling feature enabled for the Bastion Host. Defaults to false.


<a id="nestedatt--configuration--subscriptions--connectivity--backups"></a>
### Nested Schema for `configuration.subscriptions.connectivity.backups`

Optional:

- `recovery_services_vault` (Attributes) Configuration settings for Recovery Services Vault in this subscription. Defaults to `{"backup_policies":{"file_share":[{"frequency":{"daily":{"time":"23:00"},"hourly":<null>},"name":"daily","retention":{"daily":{"count":33},"monthly":<null>,"weekly":<null>,"yearly":<null>},"timezone":"UTC"},{"frequency":{"daily":{"time":"23:00"},"hourly":<null>},"name":"monthly","retention":{"daily":{"count":33},"monthly":{"count":13,"days":<null>,"include_last_days":<null>,"weekdays":["Sunday"],"weeks":["Last"]},"weekly":{"count":13,"weekdays":["Saturday"]},"yearly":<null>},"timezone":"UTC"},{"frequency":{"daily":{"time":"23:00"},"hourly":<null>},"name":"weekly","retention":{"daily":{"count":33},"monthly":<null>,"weekly":{"count":13,"weekdays":["Saturday"]},"yearly":<null>},"timezone":"UTC"},{"frequency":{"daily":{"time":"23:00"},"hourly":<null>},"name":"yearly","retention":{"daily":{"count":33},"monthly":{"count":13,"days":<null>,"include_last_days":<null>,"weekdays":["Sunday"],"weeks":["Last"]},"weekly":{"count":13,"weekdays":["Saturday"]},"yearly":{"count":7,"days":<null>,"include_last_days":<null>,"months":["January"],"weekdays":["Monday"],"weeks":["First"]}},"timezone":"UTC"}],"vm":[{"frequency":{"daily":{"time":"23:00"},"hourly":<null>,"weekly":<null>},"name":"daily","policy_type":{"v1":<null>,"v2":{"instant_restore_retention_days":7}},"retention":{"daily":{"count":33},"monthly":<null>,"weekly":<null>,"yearly":<null>},"tiering_policy":<null>,"timezone":"UTC"},{"frequency":{"daily":{"time":"23:00"},"hourly":<null>,"weekly":<null>},"name":"monthly","policy_type":{"v1":<null>,"v2":{"instant_restore_retention_days":7}},"retention":{"daily":{"count":33},"monthly":{"count":13,"days":<null>,"include_last_days":<null>,"weekdays":["Sunday"],"weeks":["Last"]},"weekly":{"count":5,"weekdays":["Saturday"]},"yearly":<null>},"tiering_policy":<null>,"timezone":"UTC"},{"frequency":{"daily":{"time":"23:00"},"hourly":<null>,"weekly":<null>},"name":"weekly","policy_type":{"v1":<null>,"v2":{"instant_restore_retention_days":7}},"retention":{"daily":{"count":33},"monthly":<null>,"weekly":{"count":5,"weekdays":["Saturday"]},"yearly":<null>},"tiering_policy":<null>,"timezone":"UTC"},{"frequency":{"daily":{"time":"23:00"},"hourly":<null>,"weekly":<null>},"name":"yearly","policy_type":{"v1":<null>,"v2":{"instant_restore_retention_days":7}},"retention":{"daily":{"count":33},"monthly":{"count":13,"days":<null>,"include_last_days":<null>,"weekdays":["Sunday"],"weeks":["Last"]},"weekly":{"count":5,"weekdays":["Saturday"]},"yearly":{"count":7,"days":<null>,"include_last_days":<null>,"months":["January"],"weekdays":["Monday"],"weeks":["First"]}},"tiering_policy":<null>,"timezone":"UTC"}]},"encryption":{"enabled":true,"infrastructure_encryption":false},"immutability":<null>,"monitoring":{"alerts_for_all_job_failures":true},"sku":"Standard","soft_delete":true,"storage_mode_type":"GeoRedundant","tags":<null>}`. (see [below for nested schema](#nestedatt--configuration--subscriptions--connectivity--backups--recovery_services_vault))

<a id="nestedatt--configuration--subscriptions--connectivity--backups--recovery_services_vault"></a>
### Nested Schema for `configuration.subscriptions.connectivity.backups.recovery_services_vault`

Optional:

- `backup_policies` (Attributes) Backup policies to be created in this Recovery Services Vault. Defaults to `{"file_share":[{"frequency":{"daily":{"time":"23:00"},"hourly":<null>},"name":"daily","retention":{"daily":{"count":33},"monthly":<null>,"weekly":<null>,"yearly":<null>},"timezone":"UTC"},{"frequency":{"daily":{"time":"23:00"},"hourly":<null>},"name":"monthly","retention":{"daily":{"count":33},"monthly":{"count":13,"days":<null>,"include_last_days":<null>,"weekdays":["Sunday"],"weeks":["Last"]},"weekly":{"count":13,"weekdays":["Saturday"]},"yearly":<null>},"timezone":"UTC"},{"frequency":{"daily":{"time":"23:00"},"hourly":<null>},"name":"weekly","retention":{"daily":{"count":33},"monthly":<null>,"weekly":{"count":13,"weekdays":["Saturday"]},"yearly":<null>},"timezone":"UTC"},{"frequency":{"daily":{"time":"23:00"},"hourly":<null>},"name":"yearly","retention":{"daily":{"count":33},"monthly":{"count":13,"days":<null>,"include_last_days":<null>,"weekdays":["Sunday"],"weeks":["Last"]},"weekly":{"count":13,"weekdays":["Saturday"]},"yearly":{"count":7,"days":<null>,"include_last_days":<null>,"months":["January"],"weekdays":["Monday"],"weeks":["First"]}},"timezone":"UTC"}],"vm":[{"frequency":{"daily":{"time":"23:00"},"hourly":<null>,"weekly":<null>},"name":"daily","policy_type":{"v1":<null>,"v2":{"instant_restore_retention_days":7}},"retention":{"daily":{"count":33},"monthly":<null>,"weekly":<null>,"yearly":<null>},"tiering_policy":<null>,"timezone":"UTC"},{"frequency":{"daily":{"time":"23:00"},"hourly":<null>,"weekly":<null>},"name":"monthly","policy_type":{"v1":<null>,"v2":{"instant_restore_retention_days":7}},"retention":{"daily":{"count":33},"monthly":{"count":13,"days":<null>,"include_last_days":<null>,"weekdays":["Sunday"],"weeks":["Last"]},"weekly":{"count":5,"weekdays":["Saturday"]},"yearly":<null>},"tiering_policy":<null>,"timezone":"UTC"},{"frequency":{"daily":{"time":"23:00"},"hourly":<null>,"weekly":<null>},"name":"weekly","policy_type":{"v1":<null>,"v2":{"instant_restore_retention_days":7}},"retention":{"daily":{"count":33},"monthly":<null>,"weekly":{"count":5,"weekdays":["Saturday"]},"yearly":<null>},"tiering_policy":<null>,"timezone":"UTC"},{"frequency":{"daily":{"time":"23:00"},"hourly":<null>,"weekly":<null>},"name":"yearly","policy_type":{"v1":<null>,"v2":{"instant_restore_retention_days":7}},"retention":{"daily":{"count":33},"monthly":{"count":13,"days":<null>,"include_last_days":<null>,"weekdays":["Sunday"],"weeks":["Last"]},"weekly":{"count":5,"weekdays":["Saturday"]},"yearly":{"count":7,"days":<null>,"include_last_days":<null>,"months":["January"],"weekdays":["Monday"],"weeks":["First"]}},"tiering_policy":<null>,"timezone":"UTC"}]}`. (see [below for nested schema](#nestedatt--configuration--subscriptions--connectivity--backups--recovery_services_vault--backup_policies))
- `encryption` (Attributes) Encryption configuration for the Recovery Services Vault. Defaults to `` (see [below for nested schema](#nestedatt--configuration--subscriptions--connectivity--backups--recovery_services_vault--encryption))
- `immutability` (String) Immutability settings of vault. Possible values are `Locked`, `Unlocked` or `Disabled`.
!!! warning
    Once `immutability` is set to `Locked`, changing it to other values forces a new Recovery Services Vault to be created.<br>
- `monitoring` (Attributes) Monitoring configuration for the Recovery Services Vault. Defaults to `` (see [below for nested schema](#nestedatt--configuration--subscriptions--connectivity--backups--recovery_services_vault--monitoring))
- `sku` (String) Sets the vault's SKU. Possible values are `Standard` or `RS0`. Defaults to `Standard`
- `soft_delete` (Boolean) Is soft delete enable for this Vault? Defaults to `true`.
- `storage_mode_type` (String) The storage type of the Recovery Services Vault. Possible values are `GeoRedundant`, `LocallyRedundant` or `ZoneRedundant`. Defaults to `GeoRedundant`.
!!! note
    If `storage_mode_type` is `GeoRedundant` and there are multiple regions defined in this subscription,    cross region restore will be enabled by default, otherwise it will be disabled.    Once cross region restore is enabled, changing it back to false forces a new Recovery Service Vault to be created.
<br>
- `tags` (Map of String) Key-value map of resource tags.

<a id="nestedatt--configuration--subscriptions--connectivity--backups--recovery_services_vault--backup_policies"></a>
### Nested Schema for `configuration.subscriptions.connectivity.backups.recovery_services_vault.backup_policies`

Optional:

- `file_share` (Attributes List) A list of file share backup policies to create. (see [below for nested schema](#nestedatt--configuration--subscriptions--connectivity--backups--recovery_services_vault--backup_policies--file_share))
- `vm` (Attributes List) A list of VM backup policies to create. (see [below for nested schema](#nestedatt--configuration--subscriptions--connectivity--backups--recovery_services_vault--backup_policies--vm))

<a id="nestedatt--configuration--subscriptions--connectivity--backups--recovery_services_vault--backup_policies--file_share"></a>
### Nested Schema for `configuration.subscriptions.connectivity.backups.recovery_services_vault.backup_policies.file_share`

Required:

- `name` (String) Backup policy name MUST be lowercase alphanumeric and dash, between 1 and 80 characters.
- `retention` (Attributes) Configures the policy retention. (see [below for nested schema](#nestedatt--configuration--subscriptions--connectivity--backups--recovery_services_vault--backup_policies--file_share--retention))

Optional:

- `frequency` (Attributes) Sets the backup frequency. Exactly one of `daily` or `hourly` MUST be specified. (see [below for nested schema](#nestedatt--configuration--subscriptions--connectivity--backups--recovery_services_vault--backup_policies--file_share--frequency))
- `timezone` (String) Specifies the Time Zone which should be used by the host pool and its associated resources for time based events, the possible values are defined [here](https://jackstromberg.com/2017/01/list-of-time-zones-consumed-by-azure/). Defaults to `UTC`.

<a id="nestedatt--configuration--subscriptions--connectivity--backups--recovery_services_vault--backup_policies--file_share--retention"></a>
### Nested Schema for `configuration.subscriptions.connectivity.backups.recovery_services_vault.backup_policies.file_share.retention`

Optional:

- `daily` (Attributes) Configures the policy daily retention. (see [below for nested schema](#nestedatt--configuration--subscriptions--connectivity--backups--recovery_services_vault--backup_policies--file_share--retention--daily))
- `monthly` (Attributes) Configures the policy monthly retention. Either `weekdays` and `weeks` or `days` and `include_last_days` must be specified. (see [below for nested schema](#nestedatt--configuration--subscriptions--connectivity--backups--recovery_services_vault--backup_policies--file_share--retention--monthly))
- `weekly` (Attributes) Configures the policy weekly retention. (see [below for nested schema](#nestedatt--configuration--subscriptions--connectivity--backups--recovery_services_vault--backup_policies--file_share--retention--weekly))
- `yearly` (Attributes) Configures the policy yearly retention. (see [below for nested schema](#nestedatt--configuration--subscriptions--connectivity--backups--recovery_services_vault--backup_policies--file_share--retention--yearly))

<a id="nestedatt--configuration--subscriptions--connectivity--backups--recovery_services_vault--backup_policies--file_share--retention--daily"></a>
### Nested Schema for `configuration.subscriptions.connectivity.backups.recovery_services_vault.backup_policies.file_share.retention.daily`

Optional:

- `count` (Number) The number of backups to keep. Must be between `1` and `200`. Defaults to `33`.


<a id="nestedatt--configuration--subscriptions--connectivity--backups--recovery_services_vault--backup_policies--file_share--retention--monthly"></a>
### Nested Schema for `configuration.subscriptions.connectivity.backups.recovery_services_vault.backup_policies.file_share.retention.monthly`

Optional:

- `count` (Number) The number of backups to keep. Must be between `1` and `120`. Defaults to `13`.
- `days` (Number) The days of the month to retain backups of. Must be between `1` and `31`. If specified, `include_last_days` MUST be specified as well and conflicts with `weekdays` and `weeks`.
- `include_last_days` (Boolean) Including the last day of the month. If specified, `days` MUST be specified as well and conflicts with `weekdays` and `weeks`.
- `weekdays` (List of String) The weekday backups to retain. Possible values are `Sunday`, `Monday`, `Tuesday`, `Wednesday`, `Thursday`, `Friday` or `Saturday`. If specified, `weeks` MUST be specified as well and conflicts with `days` and `include_last_days`.
- `weeks` (List of String) The weeks of the month to retain backups of. Possible values are `First`, `Second`, `Third`, `Fourth` or `Last`. If specified, `weekdays` MUST be specified as well and conflicts with `days` and `include_last_days`.


<a id="nestedatt--configuration--subscriptions--connectivity--backups--recovery_services_vault--backup_policies--file_share--retention--weekly"></a>
### Nested Schema for `configuration.subscriptions.connectivity.backups.recovery_services_vault.backup_policies.file_share.retention.weekly`

Optional:

- `count` (Number) The number of backups to keep. Must be between `1` and `200`. Defaults to `5`.
- `weekdays` (List of String) The weekday backups to retain. Possible values are `Sunday`, `Monday`, `Tuesday`, `Wednesday`, `Thursday`, `Friday` or `Saturday`.


<a id="nestedatt--configuration--subscriptions--connectivity--backups--recovery_services_vault--backup_policies--file_share--retention--yearly"></a>
### Nested Schema for `configuration.subscriptions.connectivity.backups.recovery_services_vault.backup_policies.file_share.retention.yearly`

Optional:

- `count` (Number) The number of backups to keep. Must be between `1` and `10`. Defaults to `7`.
- `days` (Number) The days of the month to retain backups of. Must be between `1` and `31`. If specified, `include_last_days` MUST be specified as well and conflicts with `weekdays` and `weeks`.
- `include_last_days` (Boolean) Including the last day of the month. If specified, `days` MUST be specified as well and conflicts with `weekdays` and `weeks`.
- `months` (List of String) The months of the year to retain backups of. Possible values are `January`, `February`, `March`, `April`, `May`, `June`, `July`, `August`, `September`, `October`, `November` and `December`. Defaults to `["January"]`.
- `weekdays` (List of String) The weekday backups to retain. Possible values are `Sunday`, `Monday`, `Tuesday`, `Wednesday`, `Thursday`, `Friday` or `Saturday`. If specified, `weeks` MUST be specified as well and conflicts with `days` and `include_last_days`.
- `weeks` (List of String) The weeks of the month to retain backups of. Possible values are `First`, `Second`, `Third`, `Fourth` or `Last`. If specified, `weekdays` MUST be specified as well and conflicts with `days` and `include_last_days`.



<a id="nestedatt--configuration--subscriptions--connectivity--backups--recovery_services_vault--backup_policies--file_share--frequency"></a>
### Nested Schema for `configuration.subscriptions.connectivity.backups.recovery_services_vault.backup_policies.file_share.frequency`

Optional:

- `daily` (Attributes) Sets the backup frequency to daily. Conflicts with `hourly`. (see [below for nested schema](#nestedatt--configuration--subscriptions--connectivity--backups--recovery_services_vault--backup_policies--file_share--frequency--daily))
- `hourly` (Attributes) Sets the backup frequency to hourly. Conflicts with `daily`. (see [below for nested schema](#nestedatt--configuration--subscriptions--connectivity--backups--recovery_services_vault--backup_policies--file_share--frequency--hourly))

<a id="nestedatt--configuration--subscriptions--connectivity--backups--recovery_services_vault--backup_policies--file_share--frequency--daily"></a>
### Nested Schema for `configuration.subscriptions.connectivity.backups.recovery_services_vault.backup_policies.file_share.frequency.daily`

Required:

- `time` (String) The time of day to perform the backup in 24-hour format. Times must be either on the hour or half hour (e.g. 12:00, 12:30, 13:00, etc.).


<a id="nestedatt--configuration--subscriptions--connectivity--backups--recovery_services_vault--backup_policies--file_share--frequency--hourly"></a>
### Nested Schema for `configuration.subscriptions.connectivity.backups.recovery_services_vault.backup_policies.file_share.frequency.hourly`

Required:

- `duration` (Number) Species the duration of the backup window in hours. MUST be a number between `4` and `24`. Details could be found [here](https://learn.microsoft.com/en-us/azure/backup/backup-azure-files-faq#what-does-the-duration-attribute-in-azure-files-backup-policy-signify-).
!!! note
    `duration` must be multiplier of `interval`<br>
- `interval` (Number) Specifies the interval at which backup needs to be triggered. Possible values are `4`, `6`, `8` and `12`.
- `time` (String) Specifies the start time of the hourly backup. The time format should be in 24-hour format. Times must be either on the hour or half hour (e.g. 12:00, 12:30, 13:00, etc.).




<a id="nestedatt--configuration--subscriptions--connectivity--backups--recovery_services_vault--backup_policies--vm"></a>
### Nested Schema for `configuration.subscriptions.connectivity.backups.recovery_services_vault.backup_policies.vm`

Required:

- `name` (String) Backup policy name MUST be lowercase alphanumeric and dash, between 1 and 80 characters.
- `retention` (Attributes) Configures the policy retention. (see [below for nested schema](#nestedatt--configuration--subscriptions--connectivity--backups--recovery_services_vault--backup_policies--vm--retention))

Optional:

- `frequency` (Attributes) Sets the backup frequency. Exactly one of `daily`, `hourly` or `weekly` MUST be specified. (see [below for nested schema](#nestedatt--configuration--subscriptions--connectivity--backups--recovery_services_vault--backup_policies--vm--frequency))
- `policy_type` (Attributes) Type of the Backup Policy. Possible values are `v1` or `v2`. Defaults to `{"v1":<null>,"v2":{"instant_restore_retention_days":7}}`.
!!! warning
    Changing this forces a new resource to be created.
<br> (see [below for nested schema](#nestedatt--configuration--subscriptions--connectivity--backups--recovery_services_vault--backup_policies--vm--policy_type))
- `tiering_policy` (Attributes) Tiering policy configuration. (see [below for nested schema](#nestedatt--configuration--subscriptions--connectivity--backups--recovery_services_vault--backup_policies--vm--tiering_policy))
- `timezone` (String) Specifies the Time Zone which should be used by the host pool and its associated resources for time based events, the possible values are defined [here](https://jackstromberg.com/2017/01/list-of-time-zones-consumed-by-azure/). Defaults to `UTC`.

<a id="nestedatt--configuration--subscriptions--connectivity--backups--recovery_services_vault--backup_policies--vm--retention"></a>
### Nested Schema for `configuration.subscriptions.connectivity.backups.recovery_services_vault.backup_policies.vm.retention`

Optional:

- `daily` (Attributes) Configures the policy daily retention. (see [below for nested schema](#nestedatt--configuration--subscriptions--connectivity--backups--recovery_services_vault--backup_policies--vm--retention--daily))
- `monthly` (Attributes) Configures the policy monthly retention. Either `weekdays` and `weeks` or `days` and `include_last_days` must be specified. (see [below for nested schema](#nestedatt--configuration--subscriptions--connectivity--backups--recovery_services_vault--backup_policies--vm--retention--monthly))
- `weekly` (Attributes) Configures the policy weekly retention. (see [below for nested schema](#nestedatt--configuration--subscriptions--connectivity--backups--recovery_services_vault--backup_policies--vm--retention--weekly))
- `yearly` (Attributes) Configures the policy yearly retention. (see [below for nested schema](#nestedatt--configuration--subscriptions--connectivity--backups--recovery_services_vault--backup_policies--vm--retention--yearly))

<a id="nestedatt--configuration--subscriptions--connectivity--backups--recovery_services_vault--backup_policies--vm--retention--daily"></a>
### Nested Schema for `configuration.subscriptions.connectivity.backups.recovery_services_vault.backup_policies.vm.retention.daily`

Optional:

- `count` (Number) The number of backups to keep. Must be between `7` and `9999`. Defaults to `33`.


<a id="nestedatt--configuration--subscriptions--connectivity--backups--recovery_services_vault--backup_policies--vm--retention--monthly"></a>
### Nested Schema for `configuration.subscriptions.connectivity.backups.recovery_services_vault.backup_policies.vm.retention.monthly`

Optional:

- `count` (Number) The number of backups to keep. Must be between `1` and `9999`. Defaults to `13`.
- `days` (Number) The days of the month to retain backups of. Must be between `1` and `31`. If specified, `include_last_days` MUST be specified as well and conflicts with `weekdays` and `weeks`.
- `include_last_days` (Boolean) Including the last day of the month. If specified, `days` MUST be specified as well and conflicts with `weekdays` and `weeks`.
- `weekdays` (List of String) The weekday backups to retain. Possible values are `Sunday`, `Monday`, `Tuesday`, `Wednesday`, `Thursday`, `Friday` or `Saturday`. If specified, `weeks` MUST be specified as well and conflicts with `days` and `include_last_days`.
- `weeks` (List of String) The weeks of the month to retain backups of. Possible values are `First`, `Second`, `Third`, `Fourth` or `Last`. If specified, `weekdays` MUST be specified as well and conflicts with `days` and `include_last_days`.


<a id="nestedatt--configuration--subscriptions--connectivity--backups--recovery_services_vault--backup_policies--vm--retention--weekly"></a>
### Nested Schema for `configuration.subscriptions.connectivity.backups.recovery_services_vault.backup_policies.vm.retention.weekly`

Optional:

- `count` (Number) The number of backups to keep. Must be between `1` and `9999`. Defaults to `5`.
- `weekdays` (List of String) The weekday backups to retain. Possible values are `Sunday`, `Monday`, `Tuesday`, `Wednesday`, `Thursday`, `Friday` or `Saturday`.


<a id="nestedatt--configuration--subscriptions--connectivity--backups--recovery_services_vault--backup_policies--vm--retention--yearly"></a>
### Nested Schema for `configuration.subscriptions.connectivity.backups.recovery_services_vault.backup_policies.vm.retention.yearly`

Optional:

- `count` (Number) The number of backups to keep. Must be between `1` and `9999`. Defaults to `7`.
- `days` (Number) The days of the month to retain backups of. Must be between `1` and `31`. If specified, `include_last_days` MUST be specified as well and conflicts with `weekdays` and `weeks`.
- `include_last_days` (Boolean) Including the last day of the month. If specified, `days` MUST be specified as well and conflicts with `weekdays` and `weeks`.
- `months` (List of String) The months of the year to retain backups of. Possible values are `January`, `February`, `March`, `April`, `May`, `June`, `July`, `August`, `September`, `October`, `November` and `December`. Defaults to `["January"]`.
- `weekdays` (List of String) The weekday backups to retain. Possible values are `Sunday`, `Monday`, `Tuesday`, `Wednesday`, `Thursday`, `Friday` or `Saturday`. If specified, `weeks` MUST be specified as well and conflicts with `days` and `include_last_days`.
- `weeks` (List of String) The weeks of the month to retain backups of. Possible values are `First`, `Second`, `Third`, `Fourth` or `Last`. If specified, `weekdays` MUST be specified as well and conflicts with `days` and `include_last_days`.



<a id="nestedatt--configuration--subscriptions--connectivity--backups--recovery_services_vault--backup_policies--vm--frequency"></a>
### Nested Schema for `configuration.subscriptions.connectivity.backups.recovery_services_vault.backup_policies.vm.frequency`

Optional:

- `daily` (Attributes) Sets the backup frequency to daily. Conflicts with `hourly` and `weekly`. (see [below for nested schema](#nestedatt--configuration--subscriptions--connectivity--backups--recovery_services_vault--backup_policies--vm--frequency--daily))
- `hourly` (Attributes) Sets the backup frequency to hourly. Conflicts with `daily` and `weekly`. (see [below for nested schema](#nestedatt--configuration--subscriptions--connectivity--backups--recovery_services_vault--backup_policies--vm--frequency--hourly))
- `weekly` (Attributes) Sets the backup frequency to daily. Conflicts with `daily` and `hourly`. (see [below for nested schema](#nestedatt--configuration--subscriptions--connectivity--backups--recovery_services_vault--backup_policies--vm--frequency--weekly))

<a id="nestedatt--configuration--subscriptions--connectivity--backups--recovery_services_vault--backup_policies--vm--frequency--daily"></a>
### Nested Schema for `configuration.subscriptions.connectivity.backups.recovery_services_vault.backup_policies.vm.frequency.daily`

Required:

- `time` (String) The time of day to perform the backup in 24-hour format. Times must be either on the hour or half hour (e.g. 12:00, 12:30, 13:00, etc.).


<a id="nestedatt--configuration--subscriptions--connectivity--backups--recovery_services_vault--backup_policies--vm--frequency--hourly"></a>
### Nested Schema for `configuration.subscriptions.connectivity.backups.recovery_services_vault.backup_policies.vm.frequency.hourly`

Required:

- `duration` (Number) Species the duration of the backup window in hours. MUST be a number between `4` and `24`. Details could be found [here](https://learn.microsoft.com/en-us/azure/backup/backup-azure-files-faq#what-does-the-duration-attribute-in-azure-files-backup-policy-signify-).
!!! note
    `duration` must be multiplier of `interval`<br>
- `interval` (Number) Specifies the interval at which backup needs to be triggered. Possible values are `4`, `6`, `8` and `12`.
- `time` (String) Specifies the start time of the hourly backup. The time format should be in 24-hour format. Times must be either on the hour or half hour (e.g. 12:00, 12:30, 13:00, etc.).


<a id="nestedatt--configuration--subscriptions--connectivity--backups--recovery_services_vault--backup_policies--vm--frequency--weekly"></a>
### Nested Schema for `configuration.subscriptions.connectivity.backups.recovery_services_vault.backup_policies.vm.frequency.weekly`

Required:

- `time` (String) The time of day to perform the backup in 24-hour format. Times must be either on the hour or half hour (e.g. 12:00, 12:30, 13:00, etc.
- `weekdays` (List of String) The weekday backups to retain. Possible values are `Sunday`, `Monday`, `Tuesday`, `Wednesday`, `Thursday`, `Friday` or `Saturday`.



<a id="nestedatt--configuration--subscriptions--connectivity--backups--recovery_services_vault--backup_policies--vm--policy_type"></a>
### Nested Schema for `configuration.subscriptions.connectivity.backups.recovery_services_vault.backup_policies.vm.policy_type`

Optional:

- `v1` (Attributes) Backup Policy V1 configuration. Conflicts with V2. (see [below for nested schema](#nestedatt--configuration--subscriptions--connectivity--backups--recovery_services_vault--backup_policies--vm--policy_type--v1))
- `v2` (Attributes) Backup Policy V2 (Enhanced Policy) configuration. Conflicts with V1. (see [below for nested schema](#nestedatt--configuration--subscriptions--connectivity--backups--recovery_services_vault--backup_policies--vm--policy_type--v2))

<a id="nestedatt--configuration--subscriptions--connectivity--backups--recovery_services_vault--backup_policies--vm--policy_type--v1"></a>
### Nested Schema for `configuration.subscriptions.connectivity.backups.recovery_services_vault.backup_policies.vm.policy_type.v1`

Optional:

- `instant_restore_retention_days` (Number) Specifies the instant restore retention range in days. Possible values are between 1 and 5. Defaults to `5`.!!! note
    `instant_restore_retention_days` MUST be set to `5` if the backup frequency is set to `weekly`.
<br>


<a id="nestedatt--configuration--subscriptions--connectivity--backups--recovery_services_vault--backup_policies--vm--policy_type--v2"></a>
### Nested Schema for `configuration.subscriptions.connectivity.backups.recovery_services_vault.backup_policies.vm.policy_type.v2`

Optional:

- `instant_restore_retention_days` (Number) Specifies the instant restore retention range in days. Possible values are between 1 and 30. Defaults to `7`.!!! note
    `instant_restore_retention_days` MUST be set to `5` if the backup frequency is set to `weekly`.
<br>



<a id="nestedatt--configuration--subscriptions--connectivity--backups--recovery_services_vault--backup_policies--vm--tiering_policy"></a>
### Nested Schema for `configuration.subscriptions.connectivity.backups.recovery_services_vault.backup_policies.vm.tiering_policy`

Required:

- `archived_restore_point` (Attributes) Archived restore point configuration. (see [below for nested schema](#nestedatt--configuration--subscriptions--connectivity--backups--recovery_services_vault--backup_policies--vm--tiering_policy--archived_restore_point))

<a id="nestedatt--configuration--subscriptions--connectivity--backups--recovery_services_vault--backup_policies--vm--tiering_policy--archived_restore_point"></a>
### Nested Schema for `configuration.subscriptions.connectivity.backups.recovery_services_vault.backup_policies.vm.tiering_policy.archived_restore_point`

Required:

- `mode` (String) The tiering mode to control automatic tiering of recovery points. Possible values are `TierAfter` or `TierRecommended`.

Optional:

- `duration` (Number) The number of days/weeks/months/years to retain backups in current tier before tiering.
- `duration_type` (String) The retention duration type. Possible values are `Days`, `Weeks`, `Months` or `Years`.





<a id="nestedatt--configuration--subscriptions--connectivity--backups--recovery_services_vault--encryption"></a>
### Nested Schema for `configuration.subscriptions.connectivity.backups.recovery_services_vault.encryption`

Optional:

- `enabled` (Boolean) Enabling/Disabling encryption state using the Key Vault key id created part of volocloud resource. Defaults to `true`
.!!! warning
    Once Encryption with your own key has been Enabled it's not possible to Disable it.<br>
- `infrastructure_encryption` (Boolean) Enabling/Disabling the Double Encryption state. Defaults to `false`
.!!! warning
    Once `infrastructure_encryption` has been set it's not possible to change it.<br>


<a id="nestedatt--configuration--subscriptions--connectivity--backups--recovery_services_vault--monitoring"></a>
### Nested Schema for `configuration.subscriptions.connectivity.backups.recovery_services_vault.monitoring`

Optional:

- `alerts_for_all_job_failures` (Boolean) Enabling/Disabling built-in Azure Monitor alerts for security scenarios and job failure scenarios. Defaults to `true`.




<a id="nestedatt--configuration--subscriptions--connectivity--budgets"></a>
### Nested Schema for `configuration.subscriptions.connectivity.budgets`

Required:

- `amount` (Number) The total amount of cost to track with the budget.
- `notifications` (Attributes List) One or more notification objects. (see [below for nested schema](#nestedatt--configuration--subscriptions--connectivity--budgets--notifications))

Optional:

- `time_grain` (String) The time covered by a budget. Tracking of the amount will be reset based on the time grain. Possible values are `BillingAnnual`, `BillingMonth`, `BillingQuarter`, `Annually`, `Monthly` and `Quarterly`. Defaults to `Monthly`. Changing this forces a new resource to be created.

<a id="nestedatt--configuration--subscriptions--connectivity--budgets--notifications"></a>
### Nested Schema for `configuration.subscriptions.connectivity.budgets.notifications`

Required:

- `contact_emails` (List of String) Specifies a list of email addresses to send the budget notification to when the threshold is exceeded.
- `threshold` (Number) Threshold value associated with a notification. Notification is sent when the cost exceeded the threshold. It is always percent and has to be between 0 and 1000.

Optional:

- `operator` (String) The comparison operator for the notification. Possible values are `EqualTo`, `GreaterThan`, or `GreaterThanOrEqualTo`. Defaults to `EqualTo`.
- `threshold_type` (String) The type of threshold for the notification. This determines whether the notification is triggered by forecasted costs or actual costs. The allowed values are Actual and Forecasted. Default is Actual. Changing this forces a new resource to be created.



<a id="nestedatt--configuration--subscriptions--connectivity--ddos_protection_plan"></a>
### Nested Schema for `configuration.subscriptions.connectivity.ddos_protection_plan`

Required:

- `enabled` (Boolean) Is Azure DDOS Protection Plan enabled?

Optional:

- `existing_ddos_protection_plan_resource_id` (String) Existing Azure DDOS Protection Plan resource ID to be used.


<a id="nestedatt--configuration--subscriptions--connectivity--dns_resolver"></a>
### Nested Schema for `configuration.subscriptions.connectivity.dns_resolver`

Optional:

- `inbound` (Attributes) Azure Private DNS Resolver Inbound Endpoint configuration. (see [below for nested schema](#nestedatt--configuration--subscriptions--connectivity--dns_resolver--inbound))
- `outbound` (Attributes) Azure Private DNS Resolver Outbound Endpoint configuration. (see [below for nested schema](#nestedatt--configuration--subscriptions--connectivity--dns_resolver--outbound))

<a id="nestedatt--configuration--subscriptions--connectivity--dns_resolver--inbound"></a>
### Nested Schema for `configuration.subscriptions.connectivity.dns_resolver.inbound`

Optional:

- `enabled` (Boolean) Is Azure Private DNS Resolver Inbound enpoint enabled?


<a id="nestedatt--configuration--subscriptions--connectivity--dns_resolver--outbound"></a>
### Nested Schema for `configuration.subscriptions.connectivity.dns_resolver.outbound`

Optional:

- `enabled` (Boolean) Is Azure Private Resolver DNS Outbound enpoint enabled?
- `forwarding_domains` (Attributes List) Provides a list of objects to configure outbound conditional forwarding. (see [below for nested schema](#nestedatt--configuration--subscriptions--connectivity--dns_resolver--outbound--forwarding_domains))

<a id="nestedatt--configuration--subscriptions--connectivity--dns_resolver--outbound--forwarding_domains"></a>
### Nested Schema for `configuration.subscriptions.connectivity.dns_resolver.outbound.forwarding_domains`

Required:

- `dns_domain` (String) DNS domain for conditional forwarding.
- `dns_servers` (List of String) List of DNS servers that are authoritative for the domain.




<a id="nestedatt--configuration--subscriptions--connectivity--dns_zones"></a>
### Nested Schema for `configuration.subscriptions.connectivity.dns_zones`

Optional:

- `private_subdomains` (Attributes) Map contains the private DNS domain for each environment. (see [below for nested schema](#nestedatt--configuration--subscriptions--connectivity--dns_zones--private_subdomains))
- `public_domains` (List of String) List contains the public DNS domains.

<a id="nestedatt--configuration--subscriptions--connectivity--dns_zones--private_subdomains"></a>
### Nested Schema for `configuration.subscriptions.connectivity.dns_zones.private_subdomains`

Optional:

- `dev` (String) The subdomain name for creating the DEV environment private dns zone.
- `prod` (String) The subdomain name for creating the PROD environment private dns zone.
- `qa` (String) The subdomain name for creating the QA environment private dns zone.
- `test` (String) The subdomain name for creating the TEST environment private dns zone.



<a id="nestedatt--configuration--subscriptions--connectivity--hub_networks"></a>
### Nested Schema for `configuration.subscriptions.connectivity.hub_networks`

Required:

- `enabled` (Boolean) If true, deploys a Hub and Spoke setup.

Optional:

- `azure_firewall` (Attributes) Provides details for configuring Azure Firewall service. (see [below for nested schema](#nestedatt--configuration--subscriptions--connectivity--hub_networks--azure_firewall))
- `azure_route_server` (Attributes) Creates an Azure Route Server in the HUB VNET. (see [below for nested schema](#nestedatt--configuration--subscriptions--connectivity--hub_networks--azure_route_server))
- `virtual_network_gateway` (Attributes) Provides the details to create a new virtual network gateway. (see [below for nested schema](#nestedatt--configuration--subscriptions--connectivity--hub_networks--virtual_network_gateway))

<a id="nestedatt--configuration--subscriptions--connectivity--hub_networks--azure_firewall"></a>
### Nested Schema for `configuration.subscriptions.connectivity.hub_networks.azure_firewall`

Optional:

- `availability_zones` (Boolean) Is Azure Firewall deployed across the 3 AZs? Defaults to true.
- `dns_proxy` (Boolean) Is Azure Firewall going to act as a DNS Proxy? Defaults to true.
- `dns_servers` (List of String) A list of DNS servers to configure on the Azure Firewall to use instead of Azure provided servers.
- `enabled` (Boolean) Is Azure Firewall enabled? Defaults to true.
- `policy` (Attributes) Configures Azure Firewall Policy. (see [below for nested schema](#nestedatt--configuration--subscriptions--connectivity--hub_networks--azure_firewall--policy))
- `sku` (String) SKU tier of the Firewall. Possible values are Premium, Standard and Basic. Defaults to Standard.
- `threat_intelligence_mode` (String) The operation mode for threat intelligence-based filtering. Possible values are: Off, Alert and Deny. Defaults to Alert.

<a id="nestedatt--configuration--subscriptions--connectivity--hub_networks--azure_firewall--policy"></a>
### Nested Schema for `configuration.subscriptions.connectivity.hub_networks.azure_firewall.policy`

Optional:

- `auto_learn_private_ranges_enabled` (Boolean) If true, configures the Azure Firewalll to auto-learn SNAT IP prefixes. Defaults to true.



<a id="nestedatt--configuration--subscriptions--connectivity--hub_networks--azure_route_server"></a>
### Nested Schema for `configuration.subscriptions.connectivity.hub_networks.azure_route_server`

Required:

- `enabled` (Boolean) If true, deploys an Azure Route Server in Hub VNET.

Optional:

- `attach_to_azure_firewall` (Boolean) If true, configures the deployed Azure Firewall(deployed part of Hub network) to use this Route Server. Defaults to false.
- `bgp_connections` (Attributes List) Provides a list of BGP Peer settings object. (see [below for nested schema](#nestedatt--configuration--subscriptions--connectivity--hub_networks--azure_route_server--bgp_connections))
- `branch_to_branch_traffic_enabled` (Boolean) Whether to enable route exchange between Azure Route Server and the gateway(s). Defaults to false.
- `sku` (String) The SKU of the Route Server. The only possible value is Standard. Changing this forces a new resource to be created. Defaults to Standard.

<a id="nestedatt--configuration--subscriptions--connectivity--hub_networks--azure_route_server--bgp_connections"></a>
### Nested Schema for `configuration.subscriptions.connectivity.hub_networks.azure_route_server.bgp_connections`

Required:

- `peer_asn` (Number) The BGP ASN number of the peer.
- `peer_geo` (String) The Geography Key (as defined in the geographies object under tenancy resource) where the peer needs to be configured.
- `peer_ip` (String) The IP address of the peer.
- `peer_name` (String) The name of the peer.
- `peer_region` (String) The Region Key (primary/secondary) where the peer needs to be configured.



<a id="nestedatt--configuration--subscriptions--connectivity--hub_networks--virtual_network_gateway"></a>
### Nested Schema for `configuration.subscriptions.connectivity.hub_networks.virtual_network_gateway`

Required:

- `enabled` (Boolean) Is Azure Virtual Network Gateway enabled?

Optional:

- `active_active` (Boolean) If `true`, an active-active Virtual Network Gateway will be created. An active-active gateway requires a `HighPerformance` or an `UltraPerformance` SKU. If `false`, an active-standby gateway will be created. Defaults to `false`.
- `bgp_settings` (Attributes) BGP settings for this Virtual Network Gateway. (see [below for nested schema](#nestedatt--configuration--subscriptions--connectivity--hub_networks--virtual_network_gateway--bgp_settings))
- `s2s_vpns` (Attributes List) Provides a list of objects, each object has configuration for a site-to-site VPN with a remote gateway. (see [below for nested schema](#nestedatt--configuration--subscriptions--connectivity--hub_networks--virtual_network_gateway--s2s_vpns))
- `sku` (String) Configuration of the size and capacity of the virtual network gateway. Valid options are Basic, Standard, HighPerformance, UltraPerformance, ErGw1AZ, ErGw2AZ, ErGw3AZ, VpnGw1, VpnGw2, VpnGw3, VpnGw4,VpnGw5, VpnGw1AZ, VpnGw2AZ, VpnGw3AZ,VpnGw4AZ and VpnGw5AZ and depend on the type, vpn_type and generation arguments. A PolicyBased gateway only supports the Basic SKU. Further, the UltraPerformance SKU is only supported by an ExpressRoute gateway. Defaults to Basic.
- `type` (String) The type of the Virtual Network Gateway. Valid options are Vpn or ExpressRoute. Defaults to Vpn. Changing the type forces a new resource to be created.
- `vpn_type` (String) The routing type of the Virtual Network Gateway. Valid options are RouteBased or PolicyBased. Defaults to RouteBased. Changing this forces a new resource to be created.

<a id="nestedatt--configuration--subscriptions--connectivity--hub_networks--virtual_network_gateway--bgp_settings"></a>
### Nested Schema for `configuration.subscriptions.connectivity.hub_networks.virtual_network_gateway.bgp_settings`

Optional:

- `active_active` (Attributes) BGP settings for this active-active Virtual Network Gateway. (see [below for nested schema](#nestedatt--configuration--subscriptions--connectivity--hub_networks--virtual_network_gateway--bgp_settings--active_active))
- `active_standby` (Attributes) BGP settings for this active-standby Virtual Network Gateway. (see [below for nested schema](#nestedatt--configuration--subscriptions--connectivity--hub_networks--virtual_network_gateway--bgp_settings--active_standby))

<a id="nestedatt--configuration--subscriptions--connectivity--hub_networks--virtual_network_gateway--bgp_settings--active_active"></a>
### Nested Schema for `configuration.subscriptions.connectivity.hub_networks.virtual_network_gateway.bgp_settings.active_active`

Required:

- `asn` (Number) The BGP ASN of this Virtual Network Gateway.

Optional:

- `peer_weight` (Number) The weight added to routes which have been learned through BGP peering. Valid values can be between `0` and `100`.
- `peering_apipa_addresses` (Attributes) An object with apipa addresses for this active-active Virtual Network Gateway. (see [below for nested schema](#nestedatt--configuration--subscriptions--connectivity--hub_networks--virtual_network_gateway--bgp_settings--active_active--peering_apipa_addresses))

<a id="nestedatt--configuration--subscriptions--connectivity--hub_networks--virtual_network_gateway--bgp_settings--active_active--peering_apipa_addresses"></a>
### Nested Schema for `configuration.subscriptions.connectivity.hub_networks.virtual_network_gateway.bgp_settings.active_active.peering_apipa_addresses`

Required:

- `instance_0` (Attributes) Azure primary/secondary custom APIPA addresses assigned to the instance 0 BGP peer of this active-active Virtual Network Gateway. The valid range for the reserved APIPA address in Azure Public is from `169.254.21.0` to `169.254.22.255`. (see [below for nested schema](#nestedatt--configuration--subscriptions--connectivity--hub_networks--virtual_network_gateway--bgp_settings--active_active--peering_apipa_addresses--instance_0))
- `instance_1` (Attributes) Azure primary/secondary custom APIPA addresses assigned to the instance 1 BGP peer of this active-active Virtual Network Gateway. The valid range for the reserved APIPA address in Azure Public is from `169.254.21.0` to `169.254.22.255`. (see [below for nested schema](#nestedatt--configuration--subscriptions--connectivity--hub_networks--virtual_network_gateway--bgp_settings--active_active--peering_apipa_addresses--instance_1))

<a id="nestedatt--configuration--subscriptions--connectivity--hub_networks--virtual_network_gateway--bgp_settings--active_active--peering_apipa_addresses--instance_0"></a>
### Nested Schema for `configuration.subscriptions.connectivity.hub_networks.virtual_network_gateway.bgp_settings.active_active.peering_apipa_addresses.instance_0`

Required:

- `primary` (String) Azure primary custom APIPA address assigned to the instance 0 BGP peer of this active-active Virtual Network Gateway. The valid range for the reserved APIPA address in Azure Public is from `169.254.21.0` to `169.254.22.255`.

Optional:

- `secondary` (String) Azure secondary custom APIPA address assigned to the instance 0 BGP peer of this active-active Virtual Network Gateway. The valid range for the reserved APIPA address in Azure Public is from `169.254.21.0` to `169.254.22.255`.


<a id="nestedatt--configuration--subscriptions--connectivity--hub_networks--virtual_network_gateway--bgp_settings--active_active--peering_apipa_addresses--instance_1"></a>
### Nested Schema for `configuration.subscriptions.connectivity.hub_networks.virtual_network_gateway.bgp_settings.active_active.peering_apipa_addresses.instance_1`

Required:

- `primary` (String) Azure primary custom APIPA address assigned to the instance 1 BGP peer of this active-active Virtual Network Gateway. The valid range for the reserved APIPA address in Azure Public is from `169.254.21.0` to `169.254.22.255`.

Optional:

- `secondary` (String) Azure secondary custom APIPA address assigned to the instance 1 BGP peer of this active-active Virtual Network Gateway. The valid range for the reserved APIPA address in Azure Public is from `169.254.21.0` to `169.254.22.255`.




<a id="nestedatt--configuration--subscriptions--connectivity--hub_networks--virtual_network_gateway--bgp_settings--active_standby"></a>
### Nested Schema for `configuration.subscriptions.connectivity.hub_networks.virtual_network_gateway.bgp_settings.active_standby`

Required:

- `asn` (Number) The BGP ASN of this Virtual Network Gateway.
- `peering_apipa_addresses` (Attributes) Azure primary/secondary custom APIPA addresses assigned to the BGP peer of this active-standby Virtual Network Gateway. The valid range for the reserved APIPA address in Azure Public is from `169.254.21.0` to `169.254.22.255`. (see [below for nested schema](#nestedatt--configuration--subscriptions--connectivity--hub_networks--virtual_network_gateway--bgp_settings--active_standby--peering_apipa_addresses))

Optional:

- `peer_weight` (Number) The weight added to routes which have been learned through BGP peering. Valid values can be between `0` and `100`.

<a id="nestedatt--configuration--subscriptions--connectivity--hub_networks--virtual_network_gateway--bgp_settings--active_standby--peering_apipa_addresses"></a>
### Nested Schema for `configuration.subscriptions.connectivity.hub_networks.virtual_network_gateway.bgp_settings.active_standby.peering_apipa_addresses`

Required:

- `primary` (String) Azure primary custom APIPA address assigned to the BGP peer of this active-standby Virtual Network Gateway. The valid range for the reserved APIPA address in Azure Public is from `169.254.21.0` to `169.254.22.255`.

Optional:

- `secondary` (String) Azure secondary custom APIPA address assigned to the BGP peer of this active-standby Virtual Network Gateway. The valid range for the reserved APIPA address in Azure Public is from `169.254.21.0` to `169.254.22.255`.




<a id="nestedatt--configuration--subscriptions--connectivity--hub_networks--virtual_network_gateway--s2s_vpns"></a>
### Nested Schema for `configuration.subscriptions.connectivity.hub_networks.virtual_network_gateway.s2s_vpns`

Required:

- `gateway_name` (String) The name of the local network gateway. Changing this forces a new resource to be created.

Optional:

- `connection_dpd_timeout_seconds` (Number) The dead peer detection timeout of this connection in seconds. Changing this forces a new resource to be created. Defaults to `45`
- `connection_egress_nat_rule_ids` (List of String) A list of the egress NAT Rule Ids.
- `connection_ingress_nat_rule_ids` (List of String) A list of the ingress NAT Rule Ids.
- `connection_instance` (String) Specifies the instance of this active-active Virtual Network Gateway for the connection. Valid values are `instance_0 | instance_1`.
- `connection_ipsec_policy` (Attributes) A ipsec_policy object. Only a single policy can be defined for a connection. For details on custom policies refer to the relevant section in the Azure documentation. (see [below for nested schema](#nestedatt--configuration--subscriptions--connectivity--hub_networks--virtual_network_gateway--s2s_vpns--connection_ipsec_policy))
- `connection_local_azure_ip_address_enabled` (Boolean) Use private local Azure IP for the connection. Changing this forces a new resource to be created.
- `connection_mode` (String) Connection mode to use. Possible values are Default, InitiatorOnly and ResponderOnly. Defaults to Default. Changing this value will force a resource to be created.
- `connection_protocol` (String) The IKE protocol version to use. Possible values are IKEv1 and IKEv2. Defaults to IKEv2. Changing this forces a new resource to be created. -> Note: Only valid for IPSec connections on virtual network gateways with SKU VpnGw1, VpnGw2, VpnGw3, VpnGw1AZ, VpnGw2AZ or VpnGw3AZ.
- `connection_psk_kv_secret_name` (String) The name of a KeyVault secret that has the PSK for the connection. If not provided, the code will generate a new PSK and store it in a KeyVault secret.
- `connection_type` (String) The type of connection. Valid options are IPsec (Site-to-Site), ExpressRoute (ExpressRoute), and Vnet2Vnet (VNet-to-VNet). Each connection type requires different mandatory arguments (refer to the examples above). Defaults to IPSec. Changing this forces a new resource to be created.
- `gateway_address` (String) The gateway IP address to connect with.
- `gateway_address_space` (List of String) The list of string CIDRs representing the address spaces the gateway exposes.
- `gateway_bpg_settings` (Attributes) A bgp_settings containing the Local Network Gateway's BGP speaker settings. (see [below for nested schema](#nestedatt--configuration--subscriptions--connectivity--hub_networks--virtual_network_gateway--s2s_vpns--gateway_bpg_settings))
- `gateway_fqdn` (String) The gateway FQDN to connect with.

<a id="nestedatt--configuration--subscriptions--connectivity--hub_networks--virtual_network_gateway--s2s_vpns--connection_ipsec_policy"></a>
### Nested Schema for `configuration.subscriptions.connectivity.hub_networks.virtual_network_gateway.s2s_vpns.connection_ipsec_policy`

Optional:

- `dh_group` (String) The DH group used in IKE phase 1 for initial SA. Valid options are DHGroup1, DHGroup14, DHGroup2, DHGroup2048, DHGroup24, ECP256, ECP384, or None. Defaults to DHGroup2.
- `ike_encryption` (String) The IKE encryption algorithm. Valid options are AES128, AES192, AES256, DES, DES3, GCMAES128, or GCMAES256. Defaults to AES256.
- `ike_integrity` (String) The IKE integrity algorithm. Valid options are GCMAES128, GCMAES256, MD5, SHA1, SHA256, or SHA384. Defaults to SHA256.
- `ipsec_encryption` (String) The IPSec encryption algorithm. Valid options are AES128, AES192, AES256, DES, DES3, GCMAES128, GCMAES192, GCMAES256, or None. Defaults to AES256.
- `ipsec_integrity` (String) The IPSec integrity algorithm. Valid options are GCMAES128, GCMAES192, GCMAES256, MD5, SHA1, or SHA256. Defaults to SHA256.
- `pfs_group` (String) The DH group used in IKE phase 2 for new child SA. Valid options are ECP256, ECP384, PFS1, PFS14, PFS2, PFS2048, PFS24, PFSMM, or None. Defaults to PFS2.
- `sa_datasize` (Number) The IPSec SA payload size in KB. Must be at least 1024 KB. Defaults to `102400000`.
- `sa_lifetime` (Number) The IPSec SA lifetime in seconds. Must be at least 300 seconds. Defaults to `28800` seconds.


<a id="nestedatt--configuration--subscriptions--connectivity--hub_networks--virtual_network_gateway--s2s_vpns--gateway_bpg_settings"></a>
### Nested Schema for `configuration.subscriptions.connectivity.hub_networks.virtual_network_gateway.s2s_vpns.gateway_bpg_settings`

Required:

- `asn` (String) The BGP speaker's ASN.
- `peering_address` (String) The BGP peering address and BGP identifier of this BGP speaker.

Optional:

- `peer_weight` (String) The weight added to routes learned from this BGP speaker.





<a id="nestedatt--configuration--subscriptions--connectivity--keyvault"></a>
### Nested Schema for `configuration.subscriptions.connectivity.keyvault`

Optional:

- `purge_protection_enabled` (Boolean) Is Purge Protection enabled for this Key Vault? Defaults to true.
- `sku` (String) The Name of the SKU used for this Key Vault. Possible values are standard and premium. Defaults to standard.
- `soft_delete_retention_days` (Number) The number of days that items should be retained for once soft-deleted. This field can only be configured one time and cannot be updated. This value can be between 7 and 90 days. Defaults to 90.


<a id="nestedatt--configuration--subscriptions--connectivity--resource_groups_lock"></a>
### Nested Schema for `configuration.subscriptions.connectivity.resource_groups_lock`

Optional:

- `baseline` (Boolean) Boolean flag to enable/disable RG lock. Defaults to true.
- `ddos` (Boolean) Boolean flag to enable/disable RG lock. Defaults to false.
- `dns` (Boolean) Boolean flag to enable/disable RG lock. Defaults to false.
- `rsv` (Boolean) Boolean flag to enable/disable RG lock. Defaults to false.


<a id="nestedatt--configuration--subscriptions--connectivity--vwan_hub_networks"></a>
### Nested Schema for `configuration.subscriptions.connectivity.vwan_hub_networks`

Required:

- `enabled` (Boolean) If true, deploys a VWAN setup.

Optional:

- `azure_firewall` (Attributes) Provides details for configuring Azure Firewall service. (see [below for nested schema](#nestedatt--configuration--subscriptions--connectivity--vwan_hub_networks--azure_firewall))
- `existing_virtual_wan_resource_id` (String) Existing Virtual WAN resource ID to be used.
- `expressroute_gateway` (Attributes) Manages an ExpressRoute gateway within a Virtual WAN. (see [below for nested schema](#nestedatt--configuration--subscriptions--connectivity--vwan_hub_networks--expressroute_gateway))
- `routes` (Attributes List) One or more route objects as defined below. (see [below for nested schema](#nestedatt--configuration--subscriptions--connectivity--vwan_hub_networks--routes))
- `vpn_gateway` (Attributes) Manages a VPN Gateway within a Virtual Hub, which enables Site-to-Site communication. (see [below for nested schema](#nestedatt--configuration--subscriptions--connectivity--vwan_hub_networks--vpn_gateway))

<a id="nestedatt--configuration--subscriptions--connectivity--vwan_hub_networks--azure_firewall"></a>
### Nested Schema for `configuration.subscriptions.connectivity.vwan_hub_networks.azure_firewall`

Optional:

- `availability_zones` (Boolean) Is Azure Firewall deployed across the 3 AZs? Defaults to true.
- `dns_proxy` (Boolean) Is Azure Firewall going to act as a DNS Proxy? Defaults to true.
- `dns_servers` (List of String) A list of DNS servers to configure on the Azure Firewall to use instead of Azure provided servers.
- `enabled` (Boolean) Is Azure Firewall enabled? Defaults to true.
- `sku` (String) SKU tier of the Firewall. Possible values are Premium, Standard and Basic. Defaults to Standard.
- `threat_intelligence_mode` (String) The operation mode for threat intelligence-based filtering. Possible values are: Off, Alert and Deny. Defaults to Alert.


<a id="nestedatt--configuration--subscriptions--connectivity--vwan_hub_networks--expressroute_gateway"></a>
### Nested Schema for `configuration.subscriptions.connectivity.vwan_hub_networks.expressroute_gateway`

Required:

- `enabled` (Boolean) If true, deploys Expressroute Gateway.

Optional:

- `scale_unit` (Number) The number of scale units with which to provision the ExpressRoute gateway. Each scale unit is equal to 2Gbps, with support for up to 10 scale units (20Gbps). Defaults to `1`


<a id="nestedatt--configuration--subscriptions--connectivity--vwan_hub_networks--routes"></a>
### Nested Schema for `configuration.subscriptions.connectivity.vwan_hub_networks.routes`

Required:

- `address_prefixes` (List of String) A list of Address Prefixes.
- `next_hop_ip_address` (String) The IP Address that Packets should be forwarded to as the Next Hop.


<a id="nestedatt--configuration--subscriptions--connectivity--vwan_hub_networks--vpn_gateway"></a>
### Nested Schema for `configuration.subscriptions.connectivity.vwan_hub_networks.vpn_gateway`

Required:

- `enabled` (Boolean) If true, deploys VPN Gateway.

Optional:

- `bgp_settings` (Attributes) A bgp_settings object. (see [below for nested schema](#nestedatt--configuration--subscriptions--connectivity--vwan_hub_networks--vpn_gateway--bgp_settings))
- `routing_preference` (String) Azure routing preference lets you to choose how your traffic routes between Azure and the internet. You can choose to route traffic either via the `Microsoft Network` or via the ISP network, `Internet`. Defaults to `Microsoft Network`.
- `scale_unit` (Number) The number of scale units with which to provision the VPN gateway. Each scale unit is equal to 2Gbps, with support for up to 10 scale units (20Gbps). Defaults to `1`

<a id="nestedatt--configuration--subscriptions--connectivity--vwan_hub_networks--vpn_gateway--bgp_settings"></a>
### Nested Schema for `configuration.subscriptions.connectivity.vwan_hub_networks.vpn_gateway.bgp_settings`

Required:

- `asn` (Number) The ASN of the BGP Speaker. Changing this forces a new resource to be created.
- `peer_weight` (Number) The weight added to Routes learned from this BGP Speaker. Changing this forces a new resource to be created.

Optional:

- `instance_0_bgp_peering_address` (Attributes List) An instance_bgp_peering_address object. (see [below for nested schema](#nestedatt--configuration--subscriptions--connectivity--vwan_hub_networks--vpn_gateway--bgp_settings--instance_0_bgp_peering_address))
- `instance_1_bgp_peering_address` (Attributes List) An instance_bgp_peering_address object. (see [below for nested schema](#nestedatt--configuration--subscriptions--connectivity--vwan_hub_networks--vpn_gateway--bgp_settings--instance_1_bgp_peering_address))

<a id="nestedatt--configuration--subscriptions--connectivity--vwan_hub_networks--vpn_gateway--bgp_settings--instance_0_bgp_peering_address"></a>
### Nested Schema for `configuration.subscriptions.connectivity.vwan_hub_networks.vpn_gateway.bgp_settings.instance_0_bgp_peering_address`

Required:

- `custom_ips` (List of String) A list of custom BGP peering addresses to assign to this instance.


<a id="nestedatt--configuration--subscriptions--connectivity--vwan_hub_networks--vpn_gateway--bgp_settings--instance_1_bgp_peering_address"></a>
### Nested Schema for `configuration.subscriptions.connectivity.vwan_hub_networks.vpn_gateway.bgp_settings.instance_1_bgp_peering_address`

Required:

- `custom_ips` (List of String) A list of custom BGP peering addresses to assign to this instance.






<a id="nestedatt--configuration--subscriptions--identity"></a>
### Nested Schema for `configuration.subscriptions.identity`

Required:

- `abbreviation` (String) This abbreviation will be used to uniquily identify resources created in this subscription. Only applies to resources that require Azure global uniqueness.

Optional:

- `backups` (Attributes) Configuration settings for backups in this subscription. Defaults to {"recovery_services_vault":{"backup_policies":{"file_share":[{"frequency":{"daily":{"time":"23:00"},"hourly":<null>},"name":"daily","retention":{"daily":{"count":33},"monthly":<null>,"weekly":<null>,"yearly":<null>},"timezone":"UTC"},{"frequency":{"daily":{"time":"23:00"},"hourly":<null>},"name":"monthly","retention":{"daily":{"count":33},"monthly":{"count":13,"days":<null>,"include_last_days":<null>,"weekdays":["Sunday"],"weeks":["Last"]},"weekly":{"count":13,"weekdays":["Saturday"]},"yearly":<null>},"timezone":"UTC"},{"frequency":{"daily":{"time":"23:00"},"hourly":<null>},"name":"weekly","retention":{"daily":{"count":33},"monthly":<null>,"weekly":{"count":13,"weekdays":["Saturday"]},"yearly":<null>},"timezone":"UTC"},{"frequency":{"daily":{"time":"23:00"},"hourly":<null>},"name":"yearly","retention":{"daily":{"count":33},"monthly":{"count":13,"days":<null>,"include_last_days":<null>,"weekdays":["Sunday"],"weeks":["Last"]},"weekly":{"count":13,"weekdays":["Saturday"]},"yearly":{"count":7,"days":<null>,"include_last_days":<null>,"months":["January"],"weekdays":["Monday"],"weeks":["First"]}},"timezone":"UTC"}],"vm":[{"frequency":{"daily":{"time":"23:00"},"hourly":<null>,"weekly":<null>},"name":"daily","policy_type":{"v1":<null>,"v2":{"instant_restore_retention_days":7}},"retention":{"daily":{"count":33},"monthly":<null>,"weekly":<null>,"yearly":<null>},"tiering_policy":<null>,"timezone":"UTC"},{"frequency":{"daily":{"time":"23:00"},"hourly":<null>,"weekly":<null>},"name":"monthly","policy_type":{"v1":<null>,"v2":{"instant_restore_retention_days":7}},"retention":{"daily":{"count":33},"monthly":{"count":13,"days":<null>,"include_last_days":<null>,"weekdays":["Sunday"],"weeks":["Last"]},"weekly":{"count":5,"weekdays":["Saturday"]},"yearly":<null>},"tiering_policy":<null>,"timezone":"UTC"},{"frequency":{"daily":{"time":"23:00"},"hourly":<null>,"weekly":<null>},"name":"weekly","policy_type":{"v1":<null>,"v2":{"instant_restore_retention_days":7}},"retention":{"daily":{"count":33},"monthly":<null>,"weekly":{"count":5,"weekdays":["Saturday"]},"yearly":<null>},"tiering_policy":<null>,"timezone":"UTC"},{"frequency":{"daily":{"time":"23:00"},"hourly":<null>,"weekly":<null>},"name":"yearly","policy_type":{"v1":<null>,"v2":{"instant_restore_retention_days":7}},"retention":{"daily":{"count":33},"monthly":{"count":13,"days":<null>,"include_last_days":<null>,"weekdays":["Sunday"],"weeks":["Last"]},"weekly":{"count":5,"weekdays":["Saturday"]},"yearly":{"count":7,"days":<null>,"include_last_days":<null>,"months":["January"],"weekdays":["Monday"],"weeks":["First"]}},"tiering_policy":<null>,"timezone":"UTC"}]},"encryption":{"enabled":true,"infrastructure_encryption":false},"immutability":<null>,"monitoring":{"alerts_for_all_job_failures":true},"sku":"Standard","soft_delete":true,"storage_mode_type":"GeoRedundant","tags":<null>}} (see [below for nested schema](#nestedatt--configuration--subscriptions--identity--backups))
- `budgets` (Attributes List) Provides a list of budget objects. (see [below for nested schema](#nestedatt--configuration--subscriptions--identity--budgets))
- `keyvault` (Attributes) Azure KeyVault configuration details. (see [below for nested schema](#nestedatt--configuration--subscriptions--identity--keyvault))
- `microsoft_entra_domain_services` (Attributes) Microsoft Entra Domain Services configuration details. (see [below for nested schema](#nestedatt--configuration--subscriptions--identity--microsoft_entra_domain_services))
- `resource_groups_lock` (Attributes) Configures Azure Delete Lock at Resource Groups level. (see [below for nested schema](#nestedatt--configuration--subscriptions--identity--resource_groups_lock))
- `vnet` (Attributes) Settings for customizing standard subnets and adding PaaS subnets. (see [below for nested schema](#nestedatt--configuration--subscriptions--identity--vnet))

<a id="nestedatt--configuration--subscriptions--identity--backups"></a>
### Nested Schema for `configuration.subscriptions.identity.backups`

Optional:

- `recovery_services_vault` (Attributes) Configuration settings for Recovery Services Vault in this subscription. Defaults to `{"backup_policies":{"file_share":[{"frequency":{"daily":{"time":"23:00"},"hourly":<null>},"name":"daily","retention":{"daily":{"count":33},"monthly":<null>,"weekly":<null>,"yearly":<null>},"timezone":"UTC"},{"frequency":{"daily":{"time":"23:00"},"hourly":<null>},"name":"monthly","retention":{"daily":{"count":33},"monthly":{"count":13,"days":<null>,"include_last_days":<null>,"weekdays":["Sunday"],"weeks":["Last"]},"weekly":{"count":13,"weekdays":["Saturday"]},"yearly":<null>},"timezone":"UTC"},{"frequency":{"daily":{"time":"23:00"},"hourly":<null>},"name":"weekly","retention":{"daily":{"count":33},"monthly":<null>,"weekly":{"count":13,"weekdays":["Saturday"]},"yearly":<null>},"timezone":"UTC"},{"frequency":{"daily":{"time":"23:00"},"hourly":<null>},"name":"yearly","retention":{"daily":{"count":33},"monthly":{"count":13,"days":<null>,"include_last_days":<null>,"weekdays":["Sunday"],"weeks":["Last"]},"weekly":{"count":13,"weekdays":["Saturday"]},"yearly":{"count":7,"days":<null>,"include_last_days":<null>,"months":["January"],"weekdays":["Monday"],"weeks":["First"]}},"timezone":"UTC"}],"vm":[{"frequency":{"daily":{"time":"23:00"},"hourly":<null>,"weekly":<null>},"name":"daily","policy_type":{"v1":<null>,"v2":{"instant_restore_retention_days":7}},"retention":{"daily":{"count":33},"monthly":<null>,"weekly":<null>,"yearly":<null>},"tiering_policy":<null>,"timezone":"UTC"},{"frequency":{"daily":{"time":"23:00"},"hourly":<null>,"weekly":<null>},"name":"monthly","policy_type":{"v1":<null>,"v2":{"instant_restore_retention_days":7}},"retention":{"daily":{"count":33},"monthly":{"count":13,"days":<null>,"include_last_days":<null>,"weekdays":["Sunday"],"weeks":["Last"]},"weekly":{"count":5,"weekdays":["Saturday"]},"yearly":<null>},"tiering_policy":<null>,"timezone":"UTC"},{"frequency":{"daily":{"time":"23:00"},"hourly":<null>,"weekly":<null>},"name":"weekly","policy_type":{"v1":<null>,"v2":{"instant_restore_retention_days":7}},"retention":{"daily":{"count":33},"monthly":<null>,"weekly":{"count":5,"weekdays":["Saturday"]},"yearly":<null>},"tiering_policy":<null>,"timezone":"UTC"},{"frequency":{"daily":{"time":"23:00"},"hourly":<null>,"weekly":<null>},"name":"yearly","policy_type":{"v1":<null>,"v2":{"instant_restore_retention_days":7}},"retention":{"daily":{"count":33},"monthly":{"count":13,"days":<null>,"include_last_days":<null>,"weekdays":["Sunday"],"weeks":["Last"]},"weekly":{"count":5,"weekdays":["Saturday"]},"yearly":{"count":7,"days":<null>,"include_last_days":<null>,"months":["January"],"weekdays":["Monday"],"weeks":["First"]}},"tiering_policy":<null>,"timezone":"UTC"}]},"encryption":{"enabled":true,"infrastructure_encryption":false},"immutability":<null>,"monitoring":{"alerts_for_all_job_failures":true},"sku":"Standard","soft_delete":true,"storage_mode_type":"GeoRedundant","tags":<null>}`. (see [below for nested schema](#nestedatt--configuration--subscriptions--identity--backups--recovery_services_vault))

<a id="nestedatt--configuration--subscriptions--identity--backups--recovery_services_vault"></a>
### Nested Schema for `configuration.subscriptions.identity.backups.recovery_services_vault`

Optional:

- `backup_policies` (Attributes) Backup policies to be created in this Recovery Services Vault. Defaults to `{"file_share":[{"frequency":{"daily":{"time":"23:00"},"hourly":<null>},"name":"daily","retention":{"daily":{"count":33},"monthly":<null>,"weekly":<null>,"yearly":<null>},"timezone":"UTC"},{"frequency":{"daily":{"time":"23:00"},"hourly":<null>},"name":"monthly","retention":{"daily":{"count":33},"monthly":{"count":13,"days":<null>,"include_last_days":<null>,"weekdays":["Sunday"],"weeks":["Last"]},"weekly":{"count":13,"weekdays":["Saturday"]},"yearly":<null>},"timezone":"UTC"},{"frequency":{"daily":{"time":"23:00"},"hourly":<null>},"name":"weekly","retention":{"daily":{"count":33},"monthly":<null>,"weekly":{"count":13,"weekdays":["Saturday"]},"yearly":<null>},"timezone":"UTC"},{"frequency":{"daily":{"time":"23:00"},"hourly":<null>},"name":"yearly","retention":{"daily":{"count":33},"monthly":{"count":13,"days":<null>,"include_last_days":<null>,"weekdays":["Sunday"],"weeks":["Last"]},"weekly":{"count":13,"weekdays":["Saturday"]},"yearly":{"count":7,"days":<null>,"include_last_days":<null>,"months":["January"],"weekdays":["Monday"],"weeks":["First"]}},"timezone":"UTC"}],"vm":[{"frequency":{"daily":{"time":"23:00"},"hourly":<null>,"weekly":<null>},"name":"daily","policy_type":{"v1":<null>,"v2":{"instant_restore_retention_days":7}},"retention":{"daily":{"count":33},"monthly":<null>,"weekly":<null>,"yearly":<null>},"tiering_policy":<null>,"timezone":"UTC"},{"frequency":{"daily":{"time":"23:00"},"hourly":<null>,"weekly":<null>},"name":"monthly","policy_type":{"v1":<null>,"v2":{"instant_restore_retention_days":7}},"retention":{"daily":{"count":33},"monthly":{"count":13,"days":<null>,"include_last_days":<null>,"weekdays":["Sunday"],"weeks":["Last"]},"weekly":{"count":5,"weekdays":["Saturday"]},"yearly":<null>},"tiering_policy":<null>,"timezone":"UTC"},{"frequency":{"daily":{"time":"23:00"},"hourly":<null>,"weekly":<null>},"name":"weekly","policy_type":{"v1":<null>,"v2":{"instant_restore_retention_days":7}},"retention":{"daily":{"count":33},"monthly":<null>,"weekly":{"count":5,"weekdays":["Saturday"]},"yearly":<null>},"tiering_policy":<null>,"timezone":"UTC"},{"frequency":{"daily":{"time":"23:00"},"hourly":<null>,"weekly":<null>},"name":"yearly","policy_type":{"v1":<null>,"v2":{"instant_restore_retention_days":7}},"retention":{"daily":{"count":33},"monthly":{"count":13,"days":<null>,"include_last_days":<null>,"weekdays":["Sunday"],"weeks":["Last"]},"weekly":{"count":5,"weekdays":["Saturday"]},"yearly":{"count":7,"days":<null>,"include_last_days":<null>,"months":["January"],"weekdays":["Monday"],"weeks":["First"]}},"tiering_policy":<null>,"timezone":"UTC"}]}`. (see [below for nested schema](#nestedatt--configuration--subscriptions--identity--backups--recovery_services_vault--backup_policies))
- `encryption` (Attributes) Encryption configuration for the Recovery Services Vault. Defaults to `` (see [below for nested schema](#nestedatt--configuration--subscriptions--identity--backups--recovery_services_vault--encryption))
- `immutability` (String) Immutability settings of vault. Possible values are `Locked`, `Unlocked` or `Disabled`.
!!! warning
    Once `immutability` is set to `Locked`, changing it to other values forces a new Recovery Services Vault to be created.<br>
- `monitoring` (Attributes) Monitoring configuration for the Recovery Services Vault. Defaults to `` (see [below for nested schema](#nestedatt--configuration--subscriptions--identity--backups--recovery_services_vault--monitoring))
- `sku` (String) Sets the vault's SKU. Possible values are `Standard` or `RS0`. Defaults to `Standard`
- `soft_delete` (Boolean) Is soft delete enable for this Vault? Defaults to `true`.
- `storage_mode_type` (String) The storage type of the Recovery Services Vault. Possible values are `GeoRedundant`, `LocallyRedundant` or `ZoneRedundant`. Defaults to `GeoRedundant`.
!!! note
    If `storage_mode_type` is `GeoRedundant` and there are multiple regions defined in this subscription,    cross region restore will be enabled by default, otherwise it will be disabled.    Once cross region restore is enabled, changing it back to false forces a new Recovery Service Vault to be created.
<br>
- `tags` (Map of String) Key-value map of resource tags.

<a id="nestedatt--configuration--subscriptions--identity--backups--recovery_services_vault--backup_policies"></a>
### Nested Schema for `configuration.subscriptions.identity.backups.recovery_services_vault.backup_policies`

Optional:

- `file_share` (Attributes List) A list of file share backup policies to create. (see [below for nested schema](#nestedatt--configuration--subscriptions--identity--backups--recovery_services_vault--backup_policies--file_share))
- `vm` (Attributes List) A list of VM backup policies to create. (see [below for nested schema](#nestedatt--configuration--subscriptions--identity--backups--recovery_services_vault--backup_policies--vm))

<a id="nestedatt--configuration--subscriptions--identity--backups--recovery_services_vault--backup_policies--file_share"></a>
### Nested Schema for `configuration.subscriptions.identity.backups.recovery_services_vault.backup_policies.file_share`

Required:

- `name` (String) Backup policy name MUST be lowercase alphanumeric and dash, between 1 and 80 characters.
- `retention` (Attributes) Configures the policy retention. (see [below for nested schema](#nestedatt--configuration--subscriptions--identity--backups--recovery_services_vault--backup_policies--file_share--retention))

Optional:

- `frequency` (Attributes) Sets the backup frequency. Exactly one of `daily` or `hourly` MUST be specified. (see [below for nested schema](#nestedatt--configuration--subscriptions--identity--backups--recovery_services_vault--backup_policies--file_share--frequency))
- `timezone` (String) Specifies the Time Zone which should be used by the host pool and its associated resources for time based events, the possible values are defined [here](https://jackstromberg.com/2017/01/list-of-time-zones-consumed-by-azure/). Defaults to `UTC`.

<a id="nestedatt--configuration--subscriptions--identity--backups--recovery_services_vault--backup_policies--file_share--retention"></a>
### Nested Schema for `configuration.subscriptions.identity.backups.recovery_services_vault.backup_policies.file_share.retention`

Optional:

- `daily` (Attributes) Configures the policy daily retention. (see [below for nested schema](#nestedatt--configuration--subscriptions--identity--backups--recovery_services_vault--backup_policies--file_share--retention--daily))
- `monthly` (Attributes) Configures the policy monthly retention. Either `weekdays` and `weeks` or `days` and `include_last_days` must be specified. (see [below for nested schema](#nestedatt--configuration--subscriptions--identity--backups--recovery_services_vault--backup_policies--file_share--retention--monthly))
- `weekly` (Attributes) Configures the policy weekly retention. (see [below for nested schema](#nestedatt--configuration--subscriptions--identity--backups--recovery_services_vault--backup_policies--file_share--retention--weekly))
- `yearly` (Attributes) Configures the policy yearly retention. (see [below for nested schema](#nestedatt--configuration--subscriptions--identity--backups--recovery_services_vault--backup_policies--file_share--retention--yearly))

<a id="nestedatt--configuration--subscriptions--identity--backups--recovery_services_vault--backup_policies--file_share--retention--daily"></a>
### Nested Schema for `configuration.subscriptions.identity.backups.recovery_services_vault.backup_policies.file_share.retention.daily`

Optional:

- `count` (Number) The number of backups to keep. Must be between `1` and `200`. Defaults to `33`.


<a id="nestedatt--configuration--subscriptions--identity--backups--recovery_services_vault--backup_policies--file_share--retention--monthly"></a>
### Nested Schema for `configuration.subscriptions.identity.backups.recovery_services_vault.backup_policies.file_share.retention.monthly`

Optional:

- `count` (Number) The number of backups to keep. Must be between `1` and `120`. Defaults to `13`.
- `days` (Number) The days of the month to retain backups of. Must be between `1` and `31`. If specified, `include_last_days` MUST be specified as well and conflicts with `weekdays` and `weeks`.
- `include_last_days` (Boolean) Including the last day of the month. If specified, `days` MUST be specified as well and conflicts with `weekdays` and `weeks`.
- `weekdays` (List of String) The weekday backups to retain. Possible values are `Sunday`, `Monday`, `Tuesday`, `Wednesday`, `Thursday`, `Friday` or `Saturday`. If specified, `weeks` MUST be specified as well and conflicts with `days` and `include_last_days`.
- `weeks` (List of String) The weeks of the month to retain backups of. Possible values are `First`, `Second`, `Third`, `Fourth` or `Last`. If specified, `weekdays` MUST be specified as well and conflicts with `days` and `include_last_days`.


<a id="nestedatt--configuration--subscriptions--identity--backups--recovery_services_vault--backup_policies--file_share--retention--weekly"></a>
### Nested Schema for `configuration.subscriptions.identity.backups.recovery_services_vault.backup_policies.file_share.retention.weekly`

Optional:

- `count` (Number) The number of backups to keep. Must be between `1` and `200`. Defaults to `5`.
- `weekdays` (List of String) The weekday backups to retain. Possible values are `Sunday`, `Monday`, `Tuesday`, `Wednesday`, `Thursday`, `Friday` or `Saturday`.


<a id="nestedatt--configuration--subscriptions--identity--backups--recovery_services_vault--backup_policies--file_share--retention--yearly"></a>
### Nested Schema for `configuration.subscriptions.identity.backups.recovery_services_vault.backup_policies.file_share.retention.yearly`

Optional:

- `count` (Number) The number of backups to keep. Must be between `1` and `10`. Defaults to `7`.
- `days` (Number) The days of the month to retain backups of. Must be between `1` and `31`. If specified, `include_last_days` MUST be specified as well and conflicts with `weekdays` and `weeks`.
- `include_last_days` (Boolean) Including the last day of the month. If specified, `days` MUST be specified as well and conflicts with `weekdays` and `weeks`.
- `months` (List of String) The months of the year to retain backups of. Possible values are `January`, `February`, `March`, `April`, `May`, `June`, `July`, `August`, `September`, `October`, `November` and `December`. Defaults to `["January"]`.
- `weekdays` (List of String) The weekday backups to retain. Possible values are `Sunday`, `Monday`, `Tuesday`, `Wednesday`, `Thursday`, `Friday` or `Saturday`. If specified, `weeks` MUST be specified as well and conflicts with `days` and `include_last_days`.
- `weeks` (List of String) The weeks of the month to retain backups of. Possible values are `First`, `Second`, `Third`, `Fourth` or `Last`. If specified, `weekdays` MUST be specified as well and conflicts with `days` and `include_last_days`.



<a id="nestedatt--configuration--subscriptions--identity--backups--recovery_services_vault--backup_policies--file_share--frequency"></a>
### Nested Schema for `configuration.subscriptions.identity.backups.recovery_services_vault.backup_policies.file_share.frequency`

Optional:

- `daily` (Attributes) Sets the backup frequency to daily. Conflicts with `hourly`. (see [below for nested schema](#nestedatt--configuration--subscriptions--identity--backups--recovery_services_vault--backup_policies--file_share--frequency--daily))
- `hourly` (Attributes) Sets the backup frequency to hourly. Conflicts with `daily`. (see [below for nested schema](#nestedatt--configuration--subscriptions--identity--backups--recovery_services_vault--backup_policies--file_share--frequency--hourly))

<a id="nestedatt--configuration--subscriptions--identity--backups--recovery_services_vault--backup_policies--file_share--frequency--daily"></a>
### Nested Schema for `configuration.subscriptions.identity.backups.recovery_services_vault.backup_policies.file_share.frequency.daily`

Required:

- `time` (String) The time of day to perform the backup in 24-hour format. Times must be either on the hour or half hour (e.g. 12:00, 12:30, 13:00, etc.).


<a id="nestedatt--configuration--subscriptions--identity--backups--recovery_services_vault--backup_policies--file_share--frequency--hourly"></a>
### Nested Schema for `configuration.subscriptions.identity.backups.recovery_services_vault.backup_policies.file_share.frequency.hourly`

Required:

- `duration` (Number) Species the duration of the backup window in hours. MUST be a number between `4` and `24`. Details could be found [here](https://learn.microsoft.com/en-us/azure/backup/backup-azure-files-faq#what-does-the-duration-attribute-in-azure-files-backup-policy-signify-).
!!! note
    `duration` must be multiplier of `interval`<br>
- `interval` (Number) Specifies the interval at which backup needs to be triggered. Possible values are `4`, `6`, `8` and `12`.
- `time` (String) Specifies the start time of the hourly backup. The time format should be in 24-hour format. Times must be either on the hour or half hour (e.g. 12:00, 12:30, 13:00, etc.).




<a id="nestedatt--configuration--subscriptions--identity--backups--recovery_services_vault--backup_policies--vm"></a>
### Nested Schema for `configuration.subscriptions.identity.backups.recovery_services_vault.backup_policies.vm`

Required:

- `name` (String) Backup policy name MUST be lowercase alphanumeric and dash, between 1 and 80 characters.
- `retention` (Attributes) Configures the policy retention. (see [below for nested schema](#nestedatt--configuration--subscriptions--identity--backups--recovery_services_vault--backup_policies--vm--retention))

Optional:

- `frequency` (Attributes) Sets the backup frequency. Exactly one of `daily`, `hourly` or `weekly` MUST be specified. (see [below for nested schema](#nestedatt--configuration--subscriptions--identity--backups--recovery_services_vault--backup_policies--vm--frequency))
- `policy_type` (Attributes) Type of the Backup Policy. Possible values are `v1` or `v2`. Defaults to `{"v1":<null>,"v2":{"instant_restore_retention_days":7}}`.
!!! warning
    Changing this forces a new resource to be created.
<br> (see [below for nested schema](#nestedatt--configuration--subscriptions--identity--backups--recovery_services_vault--backup_policies--vm--policy_type))
- `tiering_policy` (Attributes) Tiering policy configuration. (see [below for nested schema](#nestedatt--configuration--subscriptions--identity--backups--recovery_services_vault--backup_policies--vm--tiering_policy))
- `timezone` (String) Specifies the Time Zone which should be used by the host pool and its associated resources for time based events, the possible values are defined [here](https://jackstromberg.com/2017/01/list-of-time-zones-consumed-by-azure/). Defaults to `UTC`.

<a id="nestedatt--configuration--subscriptions--identity--backups--recovery_services_vault--backup_policies--vm--retention"></a>
### Nested Schema for `configuration.subscriptions.identity.backups.recovery_services_vault.backup_policies.vm.retention`

Optional:

- `daily` (Attributes) Configures the policy daily retention. (see [below for nested schema](#nestedatt--configuration--subscriptions--identity--backups--recovery_services_vault--backup_policies--vm--retention--daily))
- `monthly` (Attributes) Configures the policy monthly retention. Either `weekdays` and `weeks` or `days` and `include_last_days` must be specified. (see [below for nested schema](#nestedatt--configuration--subscriptions--identity--backups--recovery_services_vault--backup_policies--vm--retention--monthly))
- `weekly` (Attributes) Configures the policy weekly retention. (see [below for nested schema](#nestedatt--configuration--subscriptions--identity--backups--recovery_services_vault--backup_policies--vm--retention--weekly))
- `yearly` (Attributes) Configures the policy yearly retention. (see [below for nested schema](#nestedatt--configuration--subscriptions--identity--backups--recovery_services_vault--backup_policies--vm--retention--yearly))

<a id="nestedatt--configuration--subscriptions--identity--backups--recovery_services_vault--backup_policies--vm--retention--daily"></a>
### Nested Schema for `configuration.subscriptions.identity.backups.recovery_services_vault.backup_policies.vm.retention.daily`

Optional:

- `count` (Number) The number of backups to keep. Must be between `7` and `9999`. Defaults to `33`.


<a id="nestedatt--configuration--subscriptions--identity--backups--recovery_services_vault--backup_policies--vm--retention--monthly"></a>
### Nested Schema for `configuration.subscriptions.identity.backups.recovery_services_vault.backup_policies.vm.retention.monthly`

Optional:

- `count` (Number) The number of backups to keep. Must be between `1` and `9999`. Defaults to `13`.
- `days` (Number) The days of the month to retain backups of. Must be between `1` and `31`. If specified, `include_last_days` MUST be specified as well and conflicts with `weekdays` and `weeks`.
- `include_last_days` (Boolean) Including the last day of the month. If specified, `days` MUST be specified as well and conflicts with `weekdays` and `weeks`.
- `weekdays` (List of String) The weekday backups to retain. Possible values are `Sunday`, `Monday`, `Tuesday`, `Wednesday`, `Thursday`, `Friday` or `Saturday`. If specified, `weeks` MUST be specified as well and conflicts with `days` and `include_last_days`.
- `weeks` (List of String) The weeks of the month to retain backups of. Possible values are `First`, `Second`, `Third`, `Fourth` or `Last`. If specified, `weekdays` MUST be specified as well and conflicts with `days` and `include_last_days`.


<a id="nestedatt--configuration--subscriptions--identity--backups--recovery_services_vault--backup_policies--vm--retention--weekly"></a>
### Nested Schema for `configuration.subscriptions.identity.backups.recovery_services_vault.backup_policies.vm.retention.weekly`

Optional:

- `count` (Number) The number of backups to keep. Must be between `1` and `9999`. Defaults to `5`.
- `weekdays` (List of String) The weekday backups to retain. Possible values are `Sunday`, `Monday`, `Tuesday`, `Wednesday`, `Thursday`, `Friday` or `Saturday`.


<a id="nestedatt--configuration--subscriptions--identity--backups--recovery_services_vault--backup_policies--vm--retention--yearly"></a>
### Nested Schema for `configuration.subscriptions.identity.backups.recovery_services_vault.backup_policies.vm.retention.yearly`

Optional:

- `count` (Number) The number of backups to keep. Must be between `1` and `9999`. Defaults to `7`.
- `days` (Number) The days of the month to retain backups of. Must be between `1` and `31`. If specified, `include_last_days` MUST be specified as well and conflicts with `weekdays` and `weeks`.
- `include_last_days` (Boolean) Including the last day of the month. If specified, `days` MUST be specified as well and conflicts with `weekdays` and `weeks`.
- `months` (List of String) The months of the year to retain backups of. Possible values are `January`, `February`, `March`, `April`, `May`, `June`, `July`, `August`, `September`, `October`, `November` and `December`. Defaults to `["January"]`.
- `weekdays` (List of String) The weekday backups to retain. Possible values are `Sunday`, `Monday`, `Tuesday`, `Wednesday`, `Thursday`, `Friday` or `Saturday`. If specified, `weeks` MUST be specified as well and conflicts with `days` and `include_last_days`.
- `weeks` (List of String) The weeks of the month to retain backups of. Possible values are `First`, `Second`, `Third`, `Fourth` or `Last`. If specified, `weekdays` MUST be specified as well and conflicts with `days` and `include_last_days`.



<a id="nestedatt--configuration--subscriptions--identity--backups--recovery_services_vault--backup_policies--vm--frequency"></a>
### Nested Schema for `configuration.subscriptions.identity.backups.recovery_services_vault.backup_policies.vm.frequency`

Optional:

- `daily` (Attributes) Sets the backup frequency to daily. Conflicts with `hourly` and `weekly`. (see [below for nested schema](#nestedatt--configuration--subscriptions--identity--backups--recovery_services_vault--backup_policies--vm--frequency--daily))
- `hourly` (Attributes) Sets the backup frequency to hourly. Conflicts with `daily` and `weekly`. (see [below for nested schema](#nestedatt--configuration--subscriptions--identity--backups--recovery_services_vault--backup_policies--vm--frequency--hourly))
- `weekly` (Attributes) Sets the backup frequency to daily. Conflicts with `daily` and `hourly`. (see [below for nested schema](#nestedatt--configuration--subscriptions--identity--backups--recovery_services_vault--backup_policies--vm--frequency--weekly))

<a id="nestedatt--configuration--subscriptions--identity--backups--recovery_services_vault--backup_policies--vm--frequency--daily"></a>
### Nested Schema for `configuration.subscriptions.identity.backups.recovery_services_vault.backup_policies.vm.frequency.daily`

Required:

- `time` (String) The time of day to perform the backup in 24-hour format. Times must be either on the hour or half hour (e.g. 12:00, 12:30, 13:00, etc.).


<a id="nestedatt--configuration--subscriptions--identity--backups--recovery_services_vault--backup_policies--vm--frequency--hourly"></a>
### Nested Schema for `configuration.subscriptions.identity.backups.recovery_services_vault.backup_policies.vm.frequency.hourly`

Required:

- `duration` (Number) Species the duration of the backup window in hours. MUST be a number between `4` and `24`. Details could be found [here](https://learn.microsoft.com/en-us/azure/backup/backup-azure-files-faq#what-does-the-duration-attribute-in-azure-files-backup-policy-signify-).
!!! note
    `duration` must be multiplier of `interval`<br>
- `interval` (Number) Specifies the interval at which backup needs to be triggered. Possible values are `4`, `6`, `8` and `12`.
- `time` (String) Specifies the start time of the hourly backup. The time format should be in 24-hour format. Times must be either on the hour or half hour (e.g. 12:00, 12:30, 13:00, etc.).


<a id="nestedatt--configuration--subscriptions--identity--backups--recovery_services_vault--backup_policies--vm--frequency--weekly"></a>
### Nested Schema for `configuration.subscriptions.identity.backups.recovery_services_vault.backup_policies.vm.frequency.weekly`

Required:

- `time` (String) The time of day to perform the backup in 24-hour format. Times must be either on the hour or half hour (e.g. 12:00, 12:30, 13:00, etc.
- `weekdays` (List of String) The weekday backups to retain. Possible values are `Sunday`, `Monday`, `Tuesday`, `Wednesday`, `Thursday`, `Friday` or `Saturday`.



<a id="nestedatt--configuration--subscriptions--identity--backups--recovery_services_vault--backup_policies--vm--policy_type"></a>
### Nested Schema for `configuration.subscriptions.identity.backups.recovery_services_vault.backup_policies.vm.policy_type`

Optional:

- `v1` (Attributes) Backup Policy V1 configuration. Conflicts with V2. (see [below for nested schema](#nestedatt--configuration--subscriptions--identity--backups--recovery_services_vault--backup_policies--vm--policy_type--v1))
- `v2` (Attributes) Backup Policy V2 (Enhanced Policy) configuration. Conflicts with V1. (see [below for nested schema](#nestedatt--configuration--subscriptions--identity--backups--recovery_services_vault--backup_policies--vm--policy_type--v2))

<a id="nestedatt--configuration--subscriptions--identity--backups--recovery_services_vault--backup_policies--vm--policy_type--v1"></a>
### Nested Schema for `configuration.subscriptions.identity.backups.recovery_services_vault.backup_policies.vm.policy_type.v1`

Optional:

- `instant_restore_retention_days` (Number) Specifies the instant restore retention range in days. Possible values are between 1 and 5. Defaults to `5`.!!! note
    `instant_restore_retention_days` MUST be set to `5` if the backup frequency is set to `weekly`.
<br>


<a id="nestedatt--configuration--subscriptions--identity--backups--recovery_services_vault--backup_policies--vm--policy_type--v2"></a>
### Nested Schema for `configuration.subscriptions.identity.backups.recovery_services_vault.backup_policies.vm.policy_type.v2`

Optional:

- `instant_restore_retention_days` (Number) Specifies the instant restore retention range in days. Possible values are between 1 and 30. Defaults to `7`.!!! note
    `instant_restore_retention_days` MUST be set to `5` if the backup frequency is set to `weekly`.
<br>



<a id="nestedatt--configuration--subscriptions--identity--backups--recovery_services_vault--backup_policies--vm--tiering_policy"></a>
### Nested Schema for `configuration.subscriptions.identity.backups.recovery_services_vault.backup_policies.vm.tiering_policy`

Required:

- `archived_restore_point` (Attributes) Archived restore point configuration. (see [below for nested schema](#nestedatt--configuration--subscriptions--identity--backups--recovery_services_vault--backup_policies--vm--tiering_policy--archived_restore_point))

<a id="nestedatt--configuration--subscriptions--identity--backups--recovery_services_vault--backup_policies--vm--tiering_policy--archived_restore_point"></a>
### Nested Schema for `configuration.subscriptions.identity.backups.recovery_services_vault.backup_policies.vm.tiering_policy.archived_restore_point`

Required:

- `mode` (String) The tiering mode to control automatic tiering of recovery points. Possible values are `TierAfter` or `TierRecommended`.

Optional:

- `duration` (Number) The number of days/weeks/months/years to retain backups in current tier before tiering.
- `duration_type` (String) The retention duration type. Possible values are `Days`, `Weeks`, `Months` or `Years`.





<a id="nestedatt--configuration--subscriptions--identity--backups--recovery_services_vault--encryption"></a>
### Nested Schema for `configuration.subscriptions.identity.backups.recovery_services_vault.encryption`

Optional:

- `enabled` (Boolean) Enabling/Disabling encryption state using the Key Vault key id created part of volocloud resource. Defaults to `true`
.!!! warning
    Once Encryption with your own key has been Enabled it's not possible to Disable it.<br>
- `infrastructure_encryption` (Boolean) Enabling/Disabling the Double Encryption state. Defaults to `false`
.!!! warning
    Once `infrastructure_encryption` has been set it's not possible to change it.<br>


<a id="nestedatt--configuration--subscriptions--identity--backups--recovery_services_vault--monitoring"></a>
### Nested Schema for `configuration.subscriptions.identity.backups.recovery_services_vault.monitoring`

Optional:

- `alerts_for_all_job_failures` (Boolean) Enabling/Disabling built-in Azure Monitor alerts for security scenarios and job failure scenarios. Defaults to `true`.




<a id="nestedatt--configuration--subscriptions--identity--budgets"></a>
### Nested Schema for `configuration.subscriptions.identity.budgets`

Required:

- `amount` (Number) The total amount of cost to track with the budget.
- `notifications` (Attributes List) One or more notification objects. (see [below for nested schema](#nestedatt--configuration--subscriptions--identity--budgets--notifications))

Optional:

- `time_grain` (String) The time covered by a budget. Tracking of the amount will be reset based on the time grain. Possible values are `BillingAnnual`, `BillingMonth`, `BillingQuarter`, `Annually`, `Monthly` and `Quarterly`. Defaults to `Monthly`. Changing this forces a new resource to be created.

<a id="nestedatt--configuration--subscriptions--identity--budgets--notifications"></a>
### Nested Schema for `configuration.subscriptions.identity.budgets.notifications`

Required:

- `contact_emails` (List of String) Specifies a list of email addresses to send the budget notification to when the threshold is exceeded.
- `threshold` (Number) Threshold value associated with a notification. Notification is sent when the cost exceeded the threshold. It is always percent and has to be between 0 and 1000.

Optional:

- `operator` (String) The comparison operator for the notification. Possible values are `EqualTo`, `GreaterThan`, or `GreaterThanOrEqualTo`. Defaults to `EqualTo`.
- `threshold_type` (String) The type of threshold for the notification. This determines whether the notification is triggered by forecasted costs or actual costs. The allowed values are Actual and Forecasted. Default is Actual. Changing this forces a new resource to be created.



<a id="nestedatt--configuration--subscriptions--identity--keyvault"></a>
### Nested Schema for `configuration.subscriptions.identity.keyvault`

Optional:

- `purge_protection_enabled` (Boolean) Is Purge Protection enabled for this Key Vault? Defaults to true.
- `sku` (String) The Name of the SKU used for this Key Vault. Possible values are standard and premium. Defaults to standard.
- `soft_delete_retention_days` (Number) The number of days that items should be retained for once soft-deleted. This field can only be configured one time and cannot be updated. This value can be between 7 and 90 days. Defaults to 90.


<a id="nestedatt--configuration--subscriptions--identity--microsoft_entra_domain_services"></a>
### Nested Schema for `configuration.subscriptions.identity.microsoft_entra_domain_services`

Optional:

- `admin_vm` (Attributes) Provides configuration details for AAD DS Admin VM. (see [below for nested schema](#nestedatt--configuration--subscriptions--identity--microsoft_entra_domain_services--admin_vm))
- `enabled` (Boolean) (Oprional) Boolean flag to enable/disable Microsoft Entra Domain Services. Defaults to false.
- `notification_recipients` (List of String) Provides a list of email addresses to receive notifications from Azure AD Domain Services.
- `sku` (String) The SKU to use when provisioning the Domain Service resource. One of Standard, Enterprise or Premium. Defaults to Standard.

<a id="nestedatt--configuration--subscriptions--identity--microsoft_entra_domain_services--admin_vm"></a>
### Nested Schema for `configuration.subscriptions.identity.microsoft_entra_domain_services.admin_vm`

Optional:

- `admin_username` (String) Provides a username for the local admin of the Admin VM. Defaults to `local.admin`.
- `computer_name` (String) Provides a computer name for the Admin VM. Defaults to `medsadmin`.
- `enabled` (Boolean) If true, it will create an Admin VM based on Windows 11 Enterprise for Microsoft Entra Domain Services and join it into the AD domain. Defaults to `false`.
- `shutdown_schedule` (Attributes) Configures auto-shutdown. For more details see [Azure Documentation](https://learn.microsoft.com/en-us/azure/virtual-machines/auto-shutdown-vm?tabs=portal). (see [below for nested schema](#nestedatt--configuration--subscriptions--identity--microsoft_entra_domain_services--admin_vm--shutdown_schedule))
- `spot` (Attributes) Use Azure Spot pricing for the Microsoft Entra Domain Services Admin VM. (see [below for nested schema](#nestedatt--configuration--subscriptions--identity--microsoft_entra_domain_services--admin_vm--spot))
- `vm_size` (String) The VM Size to use for Admin VM. Must be a valid Azure VM size and available in the home region. `Defaults to `Standard_B2s`.

<a id="nestedatt--configuration--subscriptions--identity--microsoft_entra_domain_services--admin_vm--shutdown_schedule"></a>
### Nested Schema for `configuration.subscriptions.identity.microsoft_entra_domain_services.admin_vm.shutdown_schedule`

Optional:

- `enabled` (Boolean) If true, it will configure auto-shutdown for the Microsoft Entra Domain Services Admin VM. Defaults to `false`.
- `notification_email` (String) Email address to receive notification of shutdown 30 min before a shutdown event.
- `recurrence_time` (String) The time each day when the shutdown schedule takes effect. Must match the format HHmm where HH is 00-23 and mm is 00-59 (e.g. 0930, 2300, etc.). Defaults to `0000`.
- `recurrence_timezone` (String) Specifies the time zone in which the shutdown schedule takes effect. The possible values are defined [here](https://jackstromberg.com/2017/01/list-of-time-zones-consumed-by-azure/). Default is `UTC`.


<a id="nestedatt--configuration--subscriptions--identity--microsoft_entra_domain_services--admin_vm--spot"></a>
### Nested Schema for `configuration.subscriptions.identity.microsoft_entra_domain_services.admin_vm.spot`

Optional:

- `enabled` (Boolean) If true, enables Azure Spot princing for the Admin VM. Defaults to `false`. The SKU provided MUST be supported for Spot pricing, otherwise the creation of the VM will fail. Please double check Azure Region and Spot princing before selecting the SKU.
- `eviction_policy` (String) Specifies what should happen when this VM is evicted for price reasons when using a Spot instance. Possible values are `Deallocate` and `Delete`. Changing this forces a new resource to be created. Defaults to `Deallocate`.
- `max_bid_price` (Number) The maximum price you're willing to pay for this VM, in US Dollars; which must be greater than the current spot price. If this bid price falls below the current spot price the Virtual Machine will be evicted using the eviction_policy. Defaults to -1, which means that the Virtual Machine should not be evicted for price reasons.




<a id="nestedatt--configuration--subscriptions--identity--resource_groups_lock"></a>
### Nested Schema for `configuration.subscriptions.identity.resource_groups_lock`

Optional:

- `baseline` (Boolean) Boolean flag to enable/disable RG lock. Defaults to true.
- `rsv` (Boolean) Boolean flag to enable/disable RG lock. Defaults to false.


<a id="nestedatt--configuration--subscriptions--identity--vnet"></a>
### Nested Schema for `configuration.subscriptions.identity.vnet`

Optional:

- `iaas_subnets` (Attributes) Configure IaaS subnets. (see [below for nested schema](#nestedatt--configuration--subscriptions--identity--vnet--iaas_subnets))
- `vnet_link_to_private_dns_zones` (List of String) Provides a list of Azure Private DNS Zones to link to this VNET. The zones must be zones created by the volocloud provider: either PaaS private zones or custom private zones.

<a id="nestedatt--configuration--subscriptions--identity--vnet--iaas_subnets"></a>
### Nested Schema for `configuration.subscriptions.identity.vnet.iaas_subnets`

Optional:

- `app_tier` (Attributes) Enables 1 IaaS subnet for app tier services. (see [below for nested schema](#nestedatt--configuration--subscriptions--identity--vnet--iaas_subnets--app_tier))
- `entrads` (Attributes) Enables 1 IaaS subnet for Microsoft Entra Domain Services. (see [below for nested schema](#nestedatt--configuration--subscriptions--identity--vnet--iaas_subnets--entrads))

<a id="nestedatt--configuration--subscriptions--identity--vnet--iaas_subnets--app_tier"></a>
### Nested Schema for `configuration.subscriptions.identity.vnet.iaas_subnets.app_tier`

Required:

- `ip_address_netnum` (Number) Netnum is a whole number that represent the order of the resulting subnet after increasing the bits with `newbits`. For example, if given a /24 and a newbits value of 2, the resulting subnet address will have length /26. There are 4 x /26 possible resulting subnets and netnum can choose which one by provinding `0`, `1`, `2` or `3`.
- `ip_address_newbits` (Number) Newbits is the number of additional bits with which to extend the Region's `ip_address_mask`. For example, if given a /24 and a newbits value of 2, the resulting subnet address will have length /26.

Optional:

- `delegation` (Attributes) Provides details to deleted the subnet to a supported Azure service. (see [below for nested schema](#nestedatt--configuration--subscriptions--identity--vnet--iaas_subnets--app_tier--delegation))
- `service_endpoints` (List of String) The list of Service endpoints to associate with the subnet.

<a id="nestedatt--configuration--subscriptions--identity--vnet--iaas_subnets--app_tier--delegation"></a>
### Nested Schema for `configuration.subscriptions.identity.vnet.iaas_subnets.app_tier.delegation`

Required:

- `name` (String) A name for this delegation.
- `service` (String) The name of service to delegate to.

Optional:

- `actions` (List of String) A list of Actions which should be delegated. This list is specific to the service to delegate to.



<a id="nestedatt--configuration--subscriptions--identity--vnet--iaas_subnets--entrads"></a>
### Nested Schema for `configuration.subscriptions.identity.vnet.iaas_subnets.entrads`

Required:

- `ip_address_netnum` (Number) Netnum is a whole number that represent the order of the resulting subnet after increasing the bits with `newbits`. For example, if given a /24 and a newbits value of 2, the resulting subnet address will have length /26. There are 4 x /26 possible resulting subnets and netnum can choose which one by provinding `0`, `1`, `2` or `3`.
- `ip_address_newbits` (Number) Newbits is the number of additional bits with which to extend the Region's `ip_address_mask`. For example, if given a /24 and a newbits value of 2, the resulting subnet address will have length /26.

Optional:

- `delegation` (Attributes) Provides details to deleted the subnet to a supported Azure service. (see [below for nested schema](#nestedatt--configuration--subscriptions--identity--vnet--iaas_subnets--entrads--delegation))
- `service_endpoints` (List of String) The list of Service endpoints to associate with the subnet.

<a id="nestedatt--configuration--subscriptions--identity--vnet--iaas_subnets--entrads--delegation"></a>
### Nested Schema for `configuration.subscriptions.identity.vnet.iaas_subnets.entrads.delegation`

Required:

- `name` (String) A name for this delegation.
- `service` (String) The name of service to delegate to.

Optional:

- `actions` (List of String) A list of Actions which should be delegated. This list is specific to the service to delegate to.






<a id="nestedatt--configuration--subscriptions--management"></a>
### Nested Schema for `configuration.subscriptions.management`

Required:

- `abbreviation` (String) This abbreviation will be used to uniquily identify resources created in this subscription. Only applies to resources that require Azure global uniqueness.
- `mdfc` (Attributes) Configures Microsoft Defender for Cloud service. (see [below for nested schema](#nestedatt--configuration--subscriptions--management--mdfc))

Optional:

- `automation_account` (Attributes) Automation Account configuration details. (see [below for nested schema](#nestedatt--configuration--subscriptions--management--automation_account))
- `backups` (Attributes) Configuration settings for backups in this subscription. Defaults to {"recovery_services_vault":{"backup_policies":{"file_share":[{"frequency":{"daily":{"time":"23:00"},"hourly":<null>},"name":"daily","retention":{"daily":{"count":33},"monthly":<null>,"weekly":<null>,"yearly":<null>},"timezone":"UTC"},{"frequency":{"daily":{"time":"23:00"},"hourly":<null>},"name":"monthly","retention":{"daily":{"count":33},"monthly":{"count":13,"days":<null>,"include_last_days":<null>,"weekdays":["Sunday"],"weeks":["Last"]},"weekly":{"count":13,"weekdays":["Saturday"]},"yearly":<null>},"timezone":"UTC"},{"frequency":{"daily":{"time":"23:00"},"hourly":<null>},"name":"weekly","retention":{"daily":{"count":33},"monthly":<null>,"weekly":{"count":13,"weekdays":["Saturday"]},"yearly":<null>},"timezone":"UTC"},{"frequency":{"daily":{"time":"23:00"},"hourly":<null>},"name":"yearly","retention":{"daily":{"count":33},"monthly":{"count":13,"days":<null>,"include_last_days":<null>,"weekdays":["Sunday"],"weeks":["Last"]},"weekly":{"count":13,"weekdays":["Saturday"]},"yearly":{"count":7,"days":<null>,"include_last_days":<null>,"months":["January"],"weekdays":["Monday"],"weeks":["First"]}},"timezone":"UTC"}],"vm":[{"frequency":{"daily":{"time":"23:00"},"hourly":<null>,"weekly":<null>},"name":"daily","policy_type":{"v1":<null>,"v2":{"instant_restore_retention_days":7}},"retention":{"daily":{"count":33},"monthly":<null>,"weekly":<null>,"yearly":<null>},"tiering_policy":<null>,"timezone":"UTC"},{"frequency":{"daily":{"time":"23:00"},"hourly":<null>,"weekly":<null>},"name":"monthly","policy_type":{"v1":<null>,"v2":{"instant_restore_retention_days":7}},"retention":{"daily":{"count":33},"monthly":{"count":13,"days":<null>,"include_last_days":<null>,"weekdays":["Sunday"],"weeks":["Last"]},"weekly":{"count":5,"weekdays":["Saturday"]},"yearly":<null>},"tiering_policy":<null>,"timezone":"UTC"},{"frequency":{"daily":{"time":"23:00"},"hourly":<null>,"weekly":<null>},"name":"weekly","policy_type":{"v1":<null>,"v2":{"instant_restore_retention_days":7}},"retention":{"daily":{"count":33},"monthly":<null>,"weekly":{"count":5,"weekdays":["Saturday"]},"yearly":<null>},"tiering_policy":<null>,"timezone":"UTC"},{"frequency":{"daily":{"time":"23:00"},"hourly":<null>,"weekly":<null>},"name":"yearly","policy_type":{"v1":<null>,"v2":{"instant_restore_retention_days":7}},"retention":{"daily":{"count":33},"monthly":{"count":13,"days":<null>,"include_last_days":<null>,"weekdays":["Sunday"],"weeks":["Last"]},"weekly":{"count":5,"weekdays":["Saturday"]},"yearly":{"count":7,"days":<null>,"include_last_days":<null>,"months":["January"],"weekdays":["Monday"],"weeks":["First"]}},"tiering_policy":<null>,"timezone":"UTC"}]},"encryption":{"enabled":true,"infrastructure_encryption":false},"immutability":<null>,"monitoring":{"alerts_for_all_job_failures":true},"sku":"Standard","soft_delete":true,"storage_mode_type":"GeoRedundant","tags":<null>}} (see [below for nested schema](#nestedatt--configuration--subscriptions--management--backups))
- `budgets` (Attributes List) Provides a list of budget objects. (see [below for nested schema](#nestedatt--configuration--subscriptions--management--budgets))
- `keyvault` (Attributes) Azure KeyVault configuration details. (see [below for nested schema](#nestedatt--configuration--subscriptions--management--keyvault))
- `log_analytics` (Attributes) Log Analytics Workspace configuration. (see [below for nested schema](#nestedatt--configuration--subscriptions--management--log_analytics))
- `monitoring_agent` (List of String) Provides a list of Azure Monitoring Agent services to enable. To disable all services, provide an empty list. Defaults to `["uami", "vminsights_dcr", "change_tracking_dcr"]`
- `network_watcher_flow_logs` (Attributes) Network Watcher Flow Logs configuration details. (see [below for nested schema](#nestedatt--configuration--subscriptions--management--network_watcher_flow_logs))
- `resource_groups_lock` (Attributes) Configures Azure Delete Lock at Resource Groups level. (see [below for nested schema](#nestedatt--configuration--subscriptions--management--resource_groups_lock))
- `vnet` (Attributes) Settings for customizing standard subnets and adding PaaS subnets. (see [below for nested schema](#nestedatt--configuration--subscriptions--management--vnet))

<a id="nestedatt--configuration--subscriptions--management--mdfc"></a>
### Nested Schema for `configuration.subscriptions.management.mdfc`

Required:

- `email` (String) Email address to receive alerts from MDFC.

Optional:

- `enabled` (Boolean) Boolean flag to enable/disable Microsoft Defender for Cloud. Defaults to `true`.
- `services` (List of String) Provides a list of MDFC services to enable. If not provided, all services are enabled by default. To disable all services, provide an empty list.


<a id="nestedatt--configuration--subscriptions--management--automation_account"></a>
### Nested Schema for `configuration.subscriptions.management.automation_account`

Optional:

- `sku` (String) The SKU of the account. Possible values are Basic and Free. Defaults to Basic.


<a id="nestedatt--configuration--subscriptions--management--backups"></a>
### Nested Schema for `configuration.subscriptions.management.backups`

Optional:

- `recovery_services_vault` (Attributes) Configuration settings for Recovery Services Vault in this subscription. Defaults to `{"backup_policies":{"file_share":[{"frequency":{"daily":{"time":"23:00"},"hourly":<null>},"name":"daily","retention":{"daily":{"count":33},"monthly":<null>,"weekly":<null>,"yearly":<null>},"timezone":"UTC"},{"frequency":{"daily":{"time":"23:00"},"hourly":<null>},"name":"monthly","retention":{"daily":{"count":33},"monthly":{"count":13,"days":<null>,"include_last_days":<null>,"weekdays":["Sunday"],"weeks":["Last"]},"weekly":{"count":13,"weekdays":["Saturday"]},"yearly":<null>},"timezone":"UTC"},{"frequency":{"daily":{"time":"23:00"},"hourly":<null>},"name":"weekly","retention":{"daily":{"count":33},"monthly":<null>,"weekly":{"count":13,"weekdays":["Saturday"]},"yearly":<null>},"timezone":"UTC"},{"frequency":{"daily":{"time":"23:00"},"hourly":<null>},"name":"yearly","retention":{"daily":{"count":33},"monthly":{"count":13,"days":<null>,"include_last_days":<null>,"weekdays":["Sunday"],"weeks":["Last"]},"weekly":{"count":13,"weekdays":["Saturday"]},"yearly":{"count":7,"days":<null>,"include_last_days":<null>,"months":["January"],"weekdays":["Monday"],"weeks":["First"]}},"timezone":"UTC"}],"vm":[{"frequency":{"daily":{"time":"23:00"},"hourly":<null>,"weekly":<null>},"name":"daily","policy_type":{"v1":<null>,"v2":{"instant_restore_retention_days":7}},"retention":{"daily":{"count":33},"monthly":<null>,"weekly":<null>,"yearly":<null>},"tiering_policy":<null>,"timezone":"UTC"},{"frequency":{"daily":{"time":"23:00"},"hourly":<null>,"weekly":<null>},"name":"monthly","policy_type":{"v1":<null>,"v2":{"instant_restore_retention_days":7}},"retention":{"daily":{"count":33},"monthly":{"count":13,"days":<null>,"include_last_days":<null>,"weekdays":["Sunday"],"weeks":["Last"]},"weekly":{"count":5,"weekdays":["Saturday"]},"yearly":<null>},"tiering_policy":<null>,"timezone":"UTC"},{"frequency":{"daily":{"time":"23:00"},"hourly":<null>,"weekly":<null>},"name":"weekly","policy_type":{"v1":<null>,"v2":{"instant_restore_retention_days":7}},"retention":{"daily":{"count":33},"monthly":<null>,"weekly":{"count":5,"weekdays":["Saturday"]},"yearly":<null>},"tiering_policy":<null>,"timezone":"UTC"},{"frequency":{"daily":{"time":"23:00"},"hourly":<null>,"weekly":<null>},"name":"yearly","policy_type":{"v1":<null>,"v2":{"instant_restore_retention_days":7}},"retention":{"daily":{"count":33},"monthly":{"count":13,"days":<null>,"include_last_days":<null>,"weekdays":["Sunday"],"weeks":["Last"]},"weekly":{"count":5,"weekdays":["Saturday"]},"yearly":{"count":7,"days":<null>,"include_last_days":<null>,"months":["January"],"weekdays":["Monday"],"weeks":["First"]}},"tiering_policy":<null>,"timezone":"UTC"}]},"encryption":{"enabled":true,"infrastructure_encryption":false},"immutability":<null>,"monitoring":{"alerts_for_all_job_failures":true},"sku":"Standard","soft_delete":true,"storage_mode_type":"GeoRedundant","tags":<null>}`. (see [below for nested schema](#nestedatt--configuration--subscriptions--management--backups--recovery_services_vault))

<a id="nestedatt--configuration--subscriptions--management--backups--recovery_services_vault"></a>
### Nested Schema for `configuration.subscriptions.management.backups.recovery_services_vault`

Optional:

- `backup_policies` (Attributes) Backup policies to be created in this Recovery Services Vault. Defaults to `{"file_share":[{"frequency":{"daily":{"time":"23:00"},"hourly":<null>},"name":"daily","retention":{"daily":{"count":33},"monthly":<null>,"weekly":<null>,"yearly":<null>},"timezone":"UTC"},{"frequency":{"daily":{"time":"23:00"},"hourly":<null>},"name":"monthly","retention":{"daily":{"count":33},"monthly":{"count":13,"days":<null>,"include_last_days":<null>,"weekdays":["Sunday"],"weeks":["Last"]},"weekly":{"count":13,"weekdays":["Saturday"]},"yearly":<null>},"timezone":"UTC"},{"frequency":{"daily":{"time":"23:00"},"hourly":<null>},"name":"weekly","retention":{"daily":{"count":33},"monthly":<null>,"weekly":{"count":13,"weekdays":["Saturday"]},"yearly":<null>},"timezone":"UTC"},{"frequency":{"daily":{"time":"23:00"},"hourly":<null>},"name":"yearly","retention":{"daily":{"count":33},"monthly":{"count":13,"days":<null>,"include_last_days":<null>,"weekdays":["Sunday"],"weeks":["Last"]},"weekly":{"count":13,"weekdays":["Saturday"]},"yearly":{"count":7,"days":<null>,"include_last_days":<null>,"months":["January"],"weekdays":["Monday"],"weeks":["First"]}},"timezone":"UTC"}],"vm":[{"frequency":{"daily":{"time":"23:00"},"hourly":<null>,"weekly":<null>},"name":"daily","policy_type":{"v1":<null>,"v2":{"instant_restore_retention_days":7}},"retention":{"daily":{"count":33},"monthly":<null>,"weekly":<null>,"yearly":<null>},"tiering_policy":<null>,"timezone":"UTC"},{"frequency":{"daily":{"time":"23:00"},"hourly":<null>,"weekly":<null>},"name":"monthly","policy_type":{"v1":<null>,"v2":{"instant_restore_retention_days":7}},"retention":{"daily":{"count":33},"monthly":{"count":13,"days":<null>,"include_last_days":<null>,"weekdays":["Sunday"],"weeks":["Last"]},"weekly":{"count":5,"weekdays":["Saturday"]},"yearly":<null>},"tiering_policy":<null>,"timezone":"UTC"},{"frequency":{"daily":{"time":"23:00"},"hourly":<null>,"weekly":<null>},"name":"weekly","policy_type":{"v1":<null>,"v2":{"instant_restore_retention_days":7}},"retention":{"daily":{"count":33},"monthly":<null>,"weekly":{"count":5,"weekdays":["Saturday"]},"yearly":<null>},"tiering_policy":<null>,"timezone":"UTC"},{"frequency":{"daily":{"time":"23:00"},"hourly":<null>,"weekly":<null>},"name":"yearly","policy_type":{"v1":<null>,"v2":{"instant_restore_retention_days":7}},"retention":{"daily":{"count":33},"monthly":{"count":13,"days":<null>,"include_last_days":<null>,"weekdays":["Sunday"],"weeks":["Last"]},"weekly":{"count":5,"weekdays":["Saturday"]},"yearly":{"count":7,"days":<null>,"include_last_days":<null>,"months":["January"],"weekdays":["Monday"],"weeks":["First"]}},"tiering_policy":<null>,"timezone":"UTC"}]}`. (see [below for nested schema](#nestedatt--configuration--subscriptions--management--backups--recovery_services_vault--backup_policies))
- `encryption` (Attributes) Encryption configuration for the Recovery Services Vault. Defaults to `` (see [below for nested schema](#nestedatt--configuration--subscriptions--management--backups--recovery_services_vault--encryption))
- `immutability` (String) Immutability settings of vault. Possible values are `Locked`, `Unlocked` or `Disabled`.
!!! warning
    Once `immutability` is set to `Locked`, changing it to other values forces a new Recovery Services Vault to be created.<br>
- `monitoring` (Attributes) Monitoring configuration for the Recovery Services Vault. Defaults to `` (see [below for nested schema](#nestedatt--configuration--subscriptions--management--backups--recovery_services_vault--monitoring))
- `sku` (String) Sets the vault's SKU. Possible values are `Standard` or `RS0`. Defaults to `Standard`
- `soft_delete` (Boolean) Is soft delete enable for this Vault? Defaults to `true`.
- `storage_mode_type` (String) The storage type of the Recovery Services Vault. Possible values are `GeoRedundant`, `LocallyRedundant` or `ZoneRedundant`. Defaults to `GeoRedundant`.
!!! note
    If `storage_mode_type` is `GeoRedundant` and there are multiple regions defined in this subscription,    cross region restore will be enabled by default, otherwise it will be disabled.    Once cross region restore is enabled, changing it back to false forces a new Recovery Service Vault to be created.
<br>
- `tags` (Map of String) Key-value map of resource tags.

<a id="nestedatt--configuration--subscriptions--management--backups--recovery_services_vault--backup_policies"></a>
### Nested Schema for `configuration.subscriptions.management.backups.recovery_services_vault.backup_policies`

Optional:

- `file_share` (Attributes List) A list of file share backup policies to create. (see [below for nested schema](#nestedatt--configuration--subscriptions--management--backups--recovery_services_vault--backup_policies--file_share))
- `vm` (Attributes List) A list of VM backup policies to create. (see [below for nested schema](#nestedatt--configuration--subscriptions--management--backups--recovery_services_vault--backup_policies--vm))

<a id="nestedatt--configuration--subscriptions--management--backups--recovery_services_vault--backup_policies--file_share"></a>
### Nested Schema for `configuration.subscriptions.management.backups.recovery_services_vault.backup_policies.file_share`

Required:

- `name` (String) Backup policy name MUST be lowercase alphanumeric and dash, between 1 and 80 characters.
- `retention` (Attributes) Configures the policy retention. (see [below for nested schema](#nestedatt--configuration--subscriptions--management--backups--recovery_services_vault--backup_policies--file_share--retention))

Optional:

- `frequency` (Attributes) Sets the backup frequency. Exactly one of `daily` or `hourly` MUST be specified. (see [below for nested schema](#nestedatt--configuration--subscriptions--management--backups--recovery_services_vault--backup_policies--file_share--frequency))
- `timezone` (String) Specifies the Time Zone which should be used by the host pool and its associated resources for time based events, the possible values are defined [here](https://jackstromberg.com/2017/01/list-of-time-zones-consumed-by-azure/). Defaults to `UTC`.

<a id="nestedatt--configuration--subscriptions--management--backups--recovery_services_vault--backup_policies--file_share--retention"></a>
### Nested Schema for `configuration.subscriptions.management.backups.recovery_services_vault.backup_policies.file_share.retention`

Optional:

- `daily` (Attributes) Configures the policy daily retention. (see [below for nested schema](#nestedatt--configuration--subscriptions--management--backups--recovery_services_vault--backup_policies--file_share--retention--daily))
- `monthly` (Attributes) Configures the policy monthly retention. Either `weekdays` and `weeks` or `days` and `include_last_days` must be specified. (see [below for nested schema](#nestedatt--configuration--subscriptions--management--backups--recovery_services_vault--backup_policies--file_share--retention--monthly))
- `weekly` (Attributes) Configures the policy weekly retention. (see [below for nested schema](#nestedatt--configuration--subscriptions--management--backups--recovery_services_vault--backup_policies--file_share--retention--weekly))
- `yearly` (Attributes) Configures the policy yearly retention. (see [below for nested schema](#nestedatt--configuration--subscriptions--management--backups--recovery_services_vault--backup_policies--file_share--retention--yearly))

<a id="nestedatt--configuration--subscriptions--management--backups--recovery_services_vault--backup_policies--file_share--retention--daily"></a>
### Nested Schema for `configuration.subscriptions.management.backups.recovery_services_vault.backup_policies.file_share.retention.daily`

Optional:

- `count` (Number) The number of backups to keep. Must be between `1` and `200`. Defaults to `33`.


<a id="nestedatt--configuration--subscriptions--management--backups--recovery_services_vault--backup_policies--file_share--retention--monthly"></a>
### Nested Schema for `configuration.subscriptions.management.backups.recovery_services_vault.backup_policies.file_share.retention.monthly`

Optional:

- `count` (Number) The number of backups to keep. Must be between `1` and `120`. Defaults to `13`.
- `days` (Number) The days of the month to retain backups of. Must be between `1` and `31`. If specified, `include_last_days` MUST be specified as well and conflicts with `weekdays` and `weeks`.
- `include_last_days` (Boolean) Including the last day of the month. If specified, `days` MUST be specified as well and conflicts with `weekdays` and `weeks`.
- `weekdays` (List of String) The weekday backups to retain. Possible values are `Sunday`, `Monday`, `Tuesday`, `Wednesday`, `Thursday`, `Friday` or `Saturday`. If specified, `weeks` MUST be specified as well and conflicts with `days` and `include_last_days`.
- `weeks` (List of String) The weeks of the month to retain backups of. Possible values are `First`, `Second`, `Third`, `Fourth` or `Last`. If specified, `weekdays` MUST be specified as well and conflicts with `days` and `include_last_days`.


<a id="nestedatt--configuration--subscriptions--management--backups--recovery_services_vault--backup_policies--file_share--retention--weekly"></a>
### Nested Schema for `configuration.subscriptions.management.backups.recovery_services_vault.backup_policies.file_share.retention.weekly`

Optional:

- `count` (Number) The number of backups to keep. Must be between `1` and `200`. Defaults to `5`.
- `weekdays` (List of String) The weekday backups to retain. Possible values are `Sunday`, `Monday`, `Tuesday`, `Wednesday`, `Thursday`, `Friday` or `Saturday`.


<a id="nestedatt--configuration--subscriptions--management--backups--recovery_services_vault--backup_policies--file_share--retention--yearly"></a>
### Nested Schema for `configuration.subscriptions.management.backups.recovery_services_vault.backup_policies.file_share.retention.yearly`

Optional:

- `count` (Number) The number of backups to keep. Must be between `1` and `10`. Defaults to `7`.
- `days` (Number) The days of the month to retain backups of. Must be between `1` and `31`. If specified, `include_last_days` MUST be specified as well and conflicts with `weekdays` and `weeks`.
- `include_last_days` (Boolean) Including the last day of the month. If specified, `days` MUST be specified as well and conflicts with `weekdays` and `weeks`.
- `months` (List of String) The months of the year to retain backups of. Possible values are `January`, `February`, `March`, `April`, `May`, `June`, `July`, `August`, `September`, `October`, `November` and `December`. Defaults to `["January"]`.
- `weekdays` (List of String) The weekday backups to retain. Possible values are `Sunday`, `Monday`, `Tuesday`, `Wednesday`, `Thursday`, `Friday` or `Saturday`. If specified, `weeks` MUST be specified as well and conflicts with `days` and `include_last_days`.
- `weeks` (List of String) The weeks of the month to retain backups of. Possible values are `First`, `Second`, `Third`, `Fourth` or `Last`. If specified, `weekdays` MUST be specified as well and conflicts with `days` and `include_last_days`.



<a id="nestedatt--configuration--subscriptions--management--backups--recovery_services_vault--backup_policies--file_share--frequency"></a>
### Nested Schema for `configuration.subscriptions.management.backups.recovery_services_vault.backup_policies.file_share.frequency`

Optional:

- `daily` (Attributes) Sets the backup frequency to daily. Conflicts with `hourly`. (see [below for nested schema](#nestedatt--configuration--subscriptions--management--backups--recovery_services_vault--backup_policies--file_share--frequency--daily))
- `hourly` (Attributes) Sets the backup frequency to hourly. Conflicts with `daily`. (see [below for nested schema](#nestedatt--configuration--subscriptions--management--backups--recovery_services_vault--backup_policies--file_share--frequency--hourly))

<a id="nestedatt--configuration--subscriptions--management--backups--recovery_services_vault--backup_policies--file_share--frequency--daily"></a>
### Nested Schema for `configuration.subscriptions.management.backups.recovery_services_vault.backup_policies.file_share.frequency.daily`

Required:

- `time` (String) The time of day to perform the backup in 24-hour format. Times must be either on the hour or half hour (e.g. 12:00, 12:30, 13:00, etc.).


<a id="nestedatt--configuration--subscriptions--management--backups--recovery_services_vault--backup_policies--file_share--frequency--hourly"></a>
### Nested Schema for `configuration.subscriptions.management.backups.recovery_services_vault.backup_policies.file_share.frequency.hourly`

Required:

- `duration` (Number) Species the duration of the backup window in hours. MUST be a number between `4` and `24`. Details could be found [here](https://learn.microsoft.com/en-us/azure/backup/backup-azure-files-faq#what-does-the-duration-attribute-in-azure-files-backup-policy-signify-).
!!! note
    `duration` must be multiplier of `interval`<br>
- `interval` (Number) Specifies the interval at which backup needs to be triggered. Possible values are `4`, `6`, `8` and `12`.
- `time` (String) Specifies the start time of the hourly backup. The time format should be in 24-hour format. Times must be either on the hour or half hour (e.g. 12:00, 12:30, 13:00, etc.).




<a id="nestedatt--configuration--subscriptions--management--backups--recovery_services_vault--backup_policies--vm"></a>
### Nested Schema for `configuration.subscriptions.management.backups.recovery_services_vault.backup_policies.vm`

Required:

- `name` (String) Backup policy name MUST be lowercase alphanumeric and dash, between 1 and 80 characters.
- `retention` (Attributes) Configures the policy retention. (see [below for nested schema](#nestedatt--configuration--subscriptions--management--backups--recovery_services_vault--backup_policies--vm--retention))

Optional:

- `frequency` (Attributes) Sets the backup frequency. Exactly one of `daily`, `hourly` or `weekly` MUST be specified. (see [below for nested schema](#nestedatt--configuration--subscriptions--management--backups--recovery_services_vault--backup_policies--vm--frequency))
- `policy_type` (Attributes) Type of the Backup Policy. Possible values are `v1` or `v2`. Defaults to `{"v1":<null>,"v2":{"instant_restore_retention_days":7}}`.
!!! warning
    Changing this forces a new resource to be created.
<br> (see [below for nested schema](#nestedatt--configuration--subscriptions--management--backups--recovery_services_vault--backup_policies--vm--policy_type))
- `tiering_policy` (Attributes) Tiering policy configuration. (see [below for nested schema](#nestedatt--configuration--subscriptions--management--backups--recovery_services_vault--backup_policies--vm--tiering_policy))
- `timezone` (String) Specifies the Time Zone which should be used by the host pool and its associated resources for time based events, the possible values are defined [here](https://jackstromberg.com/2017/01/list-of-time-zones-consumed-by-azure/). Defaults to `UTC`.

<a id="nestedatt--configuration--subscriptions--management--backups--recovery_services_vault--backup_policies--vm--retention"></a>
### Nested Schema for `configuration.subscriptions.management.backups.recovery_services_vault.backup_policies.vm.retention`

Optional:

- `daily` (Attributes) Configures the policy daily retention. (see [below for nested schema](#nestedatt--configuration--subscriptions--management--backups--recovery_services_vault--backup_policies--vm--retention--daily))
- `monthly` (Attributes) Configures the policy monthly retention. Either `weekdays` and `weeks` or `days` and `include_last_days` must be specified. (see [below for nested schema](#nestedatt--configuration--subscriptions--management--backups--recovery_services_vault--backup_policies--vm--retention--monthly))
- `weekly` (Attributes) Configures the policy weekly retention. (see [below for nested schema](#nestedatt--configuration--subscriptions--management--backups--recovery_services_vault--backup_policies--vm--retention--weekly))
- `yearly` (Attributes) Configures the policy yearly retention. (see [below for nested schema](#nestedatt--configuration--subscriptions--management--backups--recovery_services_vault--backup_policies--vm--retention--yearly))

<a id="nestedatt--configuration--subscriptions--management--backups--recovery_services_vault--backup_policies--vm--retention--daily"></a>
### Nested Schema for `configuration.subscriptions.management.backups.recovery_services_vault.backup_policies.vm.retention.daily`

Optional:

- `count` (Number) The number of backups to keep. Must be between `7` and `9999`. Defaults to `33`.


<a id="nestedatt--configuration--subscriptions--management--backups--recovery_services_vault--backup_policies--vm--retention--monthly"></a>
### Nested Schema for `configuration.subscriptions.management.backups.recovery_services_vault.backup_policies.vm.retention.monthly`

Optional:

- `count` (Number) The number of backups to keep. Must be between `1` and `9999`. Defaults to `13`.
- `days` (Number) The days of the month to retain backups of. Must be between `1` and `31`. If specified, `include_last_days` MUST be specified as well and conflicts with `weekdays` and `weeks`.
- `include_last_days` (Boolean) Including the last day of the month. If specified, `days` MUST be specified as well and conflicts with `weekdays` and `weeks`.
- `weekdays` (List of String) The weekday backups to retain. Possible values are `Sunday`, `Monday`, `Tuesday`, `Wednesday`, `Thursday`, `Friday` or `Saturday`. If specified, `weeks` MUST be specified as well and conflicts with `days` and `include_last_days`.
- `weeks` (List of String) The weeks of the month to retain backups of. Possible values are `First`, `Second`, `Third`, `Fourth` or `Last`. If specified, `weekdays` MUST be specified as well and conflicts with `days` and `include_last_days`.


<a id="nestedatt--configuration--subscriptions--management--backups--recovery_services_vault--backup_policies--vm--retention--weekly"></a>
### Nested Schema for `configuration.subscriptions.management.backups.recovery_services_vault.backup_policies.vm.retention.weekly`

Optional:

- `count` (Number) The number of backups to keep. Must be between `1` and `9999`. Defaults to `5`.
- `weekdays` (List of String) The weekday backups to retain. Possible values are `Sunday`, `Monday`, `Tuesday`, `Wednesday`, `Thursday`, `Friday` or `Saturday`.


<a id="nestedatt--configuration--subscriptions--management--backups--recovery_services_vault--backup_policies--vm--retention--yearly"></a>
### Nested Schema for `configuration.subscriptions.management.backups.recovery_services_vault.backup_policies.vm.retention.yearly`

Optional:

- `count` (Number) The number of backups to keep. Must be between `1` and `9999`. Defaults to `7`.
- `days` (Number) The days of the month to retain backups of. Must be between `1` and `31`. If specified, `include_last_days` MUST be specified as well and conflicts with `weekdays` and `weeks`.
- `include_last_days` (Boolean) Including the last day of the month. If specified, `days` MUST be specified as well and conflicts with `weekdays` and `weeks`.
- `months` (List of String) The months of the year to retain backups of. Possible values are `January`, `February`, `March`, `April`, `May`, `June`, `July`, `August`, `September`, `October`, `November` and `December`. Defaults to `["January"]`.
- `weekdays` (List of String) The weekday backups to retain. Possible values are `Sunday`, `Monday`, `Tuesday`, `Wednesday`, `Thursday`, `Friday` or `Saturday`. If specified, `weeks` MUST be specified as well and conflicts with `days` and `include_last_days`.
- `weeks` (List of String) The weeks of the month to retain backups of. Possible values are `First`, `Second`, `Third`, `Fourth` or `Last`. If specified, `weekdays` MUST be specified as well and conflicts with `days` and `include_last_days`.



<a id="nestedatt--configuration--subscriptions--management--backups--recovery_services_vault--backup_policies--vm--frequency"></a>
### Nested Schema for `configuration.subscriptions.management.backups.recovery_services_vault.backup_policies.vm.frequency`

Optional:

- `daily` (Attributes) Sets the backup frequency to daily. Conflicts with `hourly` and `weekly`. (see [below for nested schema](#nestedatt--configuration--subscriptions--management--backups--recovery_services_vault--backup_policies--vm--frequency--daily))
- `hourly` (Attributes) Sets the backup frequency to hourly. Conflicts with `daily` and `weekly`. (see [below for nested schema](#nestedatt--configuration--subscriptions--management--backups--recovery_services_vault--backup_policies--vm--frequency--hourly))
- `weekly` (Attributes) Sets the backup frequency to daily. Conflicts with `daily` and `hourly`. (see [below for nested schema](#nestedatt--configuration--subscriptions--management--backups--recovery_services_vault--backup_policies--vm--frequency--weekly))

<a id="nestedatt--configuration--subscriptions--management--backups--recovery_services_vault--backup_policies--vm--frequency--daily"></a>
### Nested Schema for `configuration.subscriptions.management.backups.recovery_services_vault.backup_policies.vm.frequency.daily`

Required:

- `time` (String) The time of day to perform the backup in 24-hour format. Times must be either on the hour or half hour (e.g. 12:00, 12:30, 13:00, etc.).


<a id="nestedatt--configuration--subscriptions--management--backups--recovery_services_vault--backup_policies--vm--frequency--hourly"></a>
### Nested Schema for `configuration.subscriptions.management.backups.recovery_services_vault.backup_policies.vm.frequency.hourly`

Required:

- `duration` (Number) Species the duration of the backup window in hours. MUST be a number between `4` and `24`. Details could be found [here](https://learn.microsoft.com/en-us/azure/backup/backup-azure-files-faq#what-does-the-duration-attribute-in-azure-files-backup-policy-signify-).
!!! note
    `duration` must be multiplier of `interval`<br>
- `interval` (Number) Specifies the interval at which backup needs to be triggered. Possible values are `4`, `6`, `8` and `12`.
- `time` (String) Specifies the start time of the hourly backup. The time format should be in 24-hour format. Times must be either on the hour or half hour (e.g. 12:00, 12:30, 13:00, etc.).


<a id="nestedatt--configuration--subscriptions--management--backups--recovery_services_vault--backup_policies--vm--frequency--weekly"></a>
### Nested Schema for `configuration.subscriptions.management.backups.recovery_services_vault.backup_policies.vm.frequency.weekly`

Required:

- `time` (String) The time of day to perform the backup in 24-hour format. Times must be either on the hour or half hour (e.g. 12:00, 12:30, 13:00, etc.
- `weekdays` (List of String) The weekday backups to retain. Possible values are `Sunday`, `Monday`, `Tuesday`, `Wednesday`, `Thursday`, `Friday` or `Saturday`.



<a id="nestedatt--configuration--subscriptions--management--backups--recovery_services_vault--backup_policies--vm--policy_type"></a>
### Nested Schema for `configuration.subscriptions.management.backups.recovery_services_vault.backup_policies.vm.policy_type`

Optional:

- `v1` (Attributes) Backup Policy V1 configuration. Conflicts with V2. (see [below for nested schema](#nestedatt--configuration--subscriptions--management--backups--recovery_services_vault--backup_policies--vm--policy_type--v1))
- `v2` (Attributes) Backup Policy V2 (Enhanced Policy) configuration. Conflicts with V1. (see [below for nested schema](#nestedatt--configuration--subscriptions--management--backups--recovery_services_vault--backup_policies--vm--policy_type--v2))

<a id="nestedatt--configuration--subscriptions--management--backups--recovery_services_vault--backup_policies--vm--policy_type--v1"></a>
### Nested Schema for `configuration.subscriptions.management.backups.recovery_services_vault.backup_policies.vm.policy_type.v1`

Optional:

- `instant_restore_retention_days` (Number) Specifies the instant restore retention range in days. Possible values are between 1 and 5. Defaults to `5`.!!! note
    `instant_restore_retention_days` MUST be set to `5` if the backup frequency is set to `weekly`.
<br>


<a id="nestedatt--configuration--subscriptions--management--backups--recovery_services_vault--backup_policies--vm--policy_type--v2"></a>
### Nested Schema for `configuration.subscriptions.management.backups.recovery_services_vault.backup_policies.vm.policy_type.v2`

Optional:

- `instant_restore_retention_days` (Number) Specifies the instant restore retention range in days. Possible values are between 1 and 30. Defaults to `7`.!!! note
    `instant_restore_retention_days` MUST be set to `5` if the backup frequency is set to `weekly`.
<br>



<a id="nestedatt--configuration--subscriptions--management--backups--recovery_services_vault--backup_policies--vm--tiering_policy"></a>
### Nested Schema for `configuration.subscriptions.management.backups.recovery_services_vault.backup_policies.vm.tiering_policy`

Required:

- `archived_restore_point` (Attributes) Archived restore point configuration. (see [below for nested schema](#nestedatt--configuration--subscriptions--management--backups--recovery_services_vault--backup_policies--vm--tiering_policy--archived_restore_point))

<a id="nestedatt--configuration--subscriptions--management--backups--recovery_services_vault--backup_policies--vm--tiering_policy--archived_restore_point"></a>
### Nested Schema for `configuration.subscriptions.management.backups.recovery_services_vault.backup_policies.vm.tiering_policy.archived_restore_point`

Required:

- `mode` (String) The tiering mode to control automatic tiering of recovery points. Possible values are `TierAfter` or `TierRecommended`.

Optional:

- `duration` (Number) The number of days/weeks/months/years to retain backups in current tier before tiering.
- `duration_type` (String) The retention duration type. Possible values are `Days`, `Weeks`, `Months` or `Years`.





<a id="nestedatt--configuration--subscriptions--management--backups--recovery_services_vault--encryption"></a>
### Nested Schema for `configuration.subscriptions.management.backups.recovery_services_vault.encryption`

Optional:

- `enabled` (Boolean) Enabling/Disabling encryption state using the Key Vault key id created part of volocloud resource. Defaults to `true`
.!!! warning
    Once Encryption with your own key has been Enabled it's not possible to Disable it.<br>
- `infrastructure_encryption` (Boolean) Enabling/Disabling the Double Encryption state. Defaults to `false`
.!!! warning
    Once `infrastructure_encryption` has been set it's not possible to change it.<br>


<a id="nestedatt--configuration--subscriptions--management--backups--recovery_services_vault--monitoring"></a>
### Nested Schema for `configuration.subscriptions.management.backups.recovery_services_vault.monitoring`

Optional:

- `alerts_for_all_job_failures` (Boolean) Enabling/Disabling built-in Azure Monitor alerts for security scenarios and job failure scenarios. Defaults to `true`.




<a id="nestedatt--configuration--subscriptions--management--budgets"></a>
### Nested Schema for `configuration.subscriptions.management.budgets`

Required:

- `amount` (Number) The total amount of cost to track with the budget.
- `notifications` (Attributes List) One or more notification objects. (see [below for nested schema](#nestedatt--configuration--subscriptions--management--budgets--notifications))

Optional:

- `time_grain` (String) The time covered by a budget. Tracking of the amount will be reset based on the time grain. Possible values are `BillingAnnual`, `BillingMonth`, `BillingQuarter`, `Annually`, `Monthly` and `Quarterly`. Defaults to `Monthly`. Changing this forces a new resource to be created.

<a id="nestedatt--configuration--subscriptions--management--budgets--notifications"></a>
### Nested Schema for `configuration.subscriptions.management.budgets.notifications`

Required:

- `contact_emails` (List of String) Specifies a list of email addresses to send the budget notification to when the threshold is exceeded.
- `threshold` (Number) Threshold value associated with a notification. Notification is sent when the cost exceeded the threshold. It is always percent and has to be between 0 and 1000.

Optional:

- `operator` (String) The comparison operator for the notification. Possible values are `EqualTo`, `GreaterThan`, or `GreaterThanOrEqualTo`. Defaults to `EqualTo`.
- `threshold_type` (String) The type of threshold for the notification. This determines whether the notification is triggered by forecasted costs or actual costs. The allowed values are Actual and Forecasted. Default is Actual. Changing this forces a new resource to be created.



<a id="nestedatt--configuration--subscriptions--management--keyvault"></a>
### Nested Schema for `configuration.subscriptions.management.keyvault`

Optional:

- `purge_protection_enabled` (Boolean) Is Purge Protection enabled for this Key Vault? Defaults to true.
- `sku` (String) The Name of the SKU used for this Key Vault. Possible values are standard and premium. Defaults to standard.
- `soft_delete_retention_days` (Number) The number of days that items should be retained for once soft-deleted. This field can only be configured one time and cannot be updated. This value can be between 7 and 90 days. Defaults to 90.


<a id="nestedatt--configuration--subscriptions--management--log_analytics"></a>
### Nested Schema for `configuration.subscriptions.management.log_analytics`

Optional:

- `daily_quota_gb` (Number) The workspace daily quota for ingestion in GB. Defaults to -1 (unlimited).
- `internet_ingestion_enabled` (Boolean) Should the Log Analytics Workspace support ingestion over the Public Internet? Defaults to true.
- `internet_query_enabled` (Boolean) Should the Log Analytics Workspace support querying over the Public Internet? Defaults to true.
- `reservation_capacity_in_gb_per_day` (Number) The capacity reservation level in GB for this workspace. Must be in increments of 100 between 100 and 5000.
- `retention_in_days` (Number) The workspace data retention in days. Possible values are either 7 (Free Tier only) or range between 30 and 730. Defaults to 30.
- `sku` (String) Specifies the SKU of the Log Analytics Workspace. Possible values are Free, PerNode, Premium, Standard, Standalone, Unlimited, CapacityReservation, and PerGB2018 (new SKU as of 2018-04-03). Defaults to PerGB2018.
- `solutions` (List of String) List of solutions to deploy to the Log Analytics Workspace. Defaults to ["monitoring_for_vm", "monitoring_for_vmss", "solution_for_change_tracking"]


<a id="nestedatt--configuration--subscriptions--management--network_watcher_flow_logs"></a>
### Nested Schema for `configuration.subscriptions.management.network_watcher_flow_logs`

Optional:

- `retention_policy` (Attributes) A retention_policy object. (see [below for nested schema](#nestedatt--configuration--subscriptions--management--network_watcher_flow_logs--retention_policy))
- `traffic_analytics` (Attributes) A traffic_analytics object. (see [below for nested schema](#nestedatt--configuration--subscriptions--management--network_watcher_flow_logs--traffic_analytics))

<a id="nestedatt--configuration--subscriptions--management--network_watcher_flow_logs--retention_policy"></a>
### Nested Schema for `configuration.subscriptions.management.network_watcher_flow_logs.retention_policy`

Optional:

- `days` (Number) The number of days to retain flow log records. Defaults to 30 days.
- `enabled` (Boolean) Boolean flag to enable/disable retention. Defaults to true.


<a id="nestedatt--configuration--subscriptions--management--network_watcher_flow_logs--traffic_analytics"></a>
### Nested Schema for `configuration.subscriptions.management.network_watcher_flow_logs.traffic_analytics`

Optional:

- `enabled` (Boolean) Boolean flag to enable/disable traffic analytics. Defaults to false.
- `interval_in_minutes` (Number) How frequently service should do flow analytics in minutes. Defaults to 60.



<a id="nestedatt--configuration--subscriptions--management--resource_groups_lock"></a>
### Nested Schema for `configuration.subscriptions.management.resource_groups_lock`

Optional:

- `baseline` (Boolean) Boolean flag to enable/disable RG lock. Defaults to true.
- `rsv` (Boolean) Boolean flag to enable/disable RG lock. Defaults to false.


<a id="nestedatt--configuration--subscriptions--management--vnet"></a>
### Nested Schema for `configuration.subscriptions.management.vnet`

Optional:

- `iaas_subnets` (Attributes) Configure IaaS subnets. (see [below for nested schema](#nestedatt--configuration--subscriptions--management--vnet--iaas_subnets))
- `paas_subnets` (Attributes) Configure PaaS subnets. (see [below for nested schema](#nestedatt--configuration--subscriptions--management--vnet--paas_subnets))
- `vnet_link_to_private_dns_zones` (List of String) Provides a list of Azure Private DNS Zones to link to this VNET. The zones must be zones created by the volocloud provider: either PaaS private zones or custom private zones.

<a id="nestedatt--configuration--subscriptions--management--vnet--iaas_subnets"></a>
### Nested Schema for `configuration.subscriptions.management.vnet.iaas_subnets`

Optional:

- `app_tier` (Attributes) Enables 1 IaaS subnet for app tier services. (see [below for nested schema](#nestedatt--configuration--subscriptions--management--vnet--iaas_subnets--app_tier))
- `data_tier` (Attributes) Enables 1 IaaS subnet for data tier services. (see [below for nested schema](#nestedatt--configuration--subscriptions--management--vnet--iaas_subnets--data_tier))
- `web_tier` (Attributes) Enables 1 IaaS subnet for web tier (internet facing) services. (see [below for nested schema](#nestedatt--configuration--subscriptions--management--vnet--iaas_subnets--web_tier))

<a id="nestedatt--configuration--subscriptions--management--vnet--iaas_subnets--app_tier"></a>
### Nested Schema for `configuration.subscriptions.management.vnet.iaas_subnets.app_tier`

Required:

- `ip_address_netnum` (Number) Netnum is a whole number that represent the order of the resulting subnet after increasing the bits with `newbits`. For example, if given a /24 and a newbits value of 2, the resulting subnet address will have length /26. There are 4 x /26 possible resulting subnets and netnum can choose which one by provinding `0`, `1`, `2` or `3`.
- `ip_address_newbits` (Number) Newbits is the number of additional bits with which to extend the Region's `ip_address_mask`. For example, if given a /24 and a newbits value of 2, the resulting subnet address will have length /26.

Optional:

- `delegation` (Attributes) Provides details to deleted the subnet to a supported Azure service. (see [below for nested schema](#nestedatt--configuration--subscriptions--management--vnet--iaas_subnets--app_tier--delegation))
- `service_endpoints` (List of String) The list of Service endpoints to associate with the subnet.

<a id="nestedatt--configuration--subscriptions--management--vnet--iaas_subnets--app_tier--delegation"></a>
### Nested Schema for `configuration.subscriptions.management.vnet.iaas_subnets.app_tier.delegation`

Required:

- `name` (String) A name for this delegation.
- `service` (String) The name of service to delegate to.

Optional:

- `actions` (List of String) A list of Actions which should be delegated. This list is specific to the service to delegate to.



<a id="nestedatt--configuration--subscriptions--management--vnet--iaas_subnets--data_tier"></a>
### Nested Schema for `configuration.subscriptions.management.vnet.iaas_subnets.data_tier`

Required:

- `ip_address_netnum` (Number) Netnum is a whole number that represent the order of the resulting subnet after increasing the bits with `newbits`. For example, if given a /24 and a newbits value of 2, the resulting subnet address will have length /26. There are 4 x /26 possible resulting subnets and netnum can choose which one by provinding `0`, `1`, `2` or `3`.
- `ip_address_newbits` (Number) Newbits is the number of additional bits with which to extend the Region's `ip_address_mask`. For example, if given a /24 and a newbits value of 2, the resulting subnet address will have length /26.

Optional:

- `delegation` (Attributes) Provides details to deleted the subnet to a supported Azure service. (see [below for nested schema](#nestedatt--configuration--subscriptions--management--vnet--iaas_subnets--data_tier--delegation))
- `service_endpoints` (List of String) The list of Service endpoints to associate with the subnet.

<a id="nestedatt--configuration--subscriptions--management--vnet--iaas_subnets--data_tier--delegation"></a>
### Nested Schema for `configuration.subscriptions.management.vnet.iaas_subnets.data_tier.delegation`

Required:

- `name` (String) A name for this delegation.
- `service` (String) The name of service to delegate to.

Optional:

- `actions` (List of String) A list of Actions which should be delegated. This list is specific to the service to delegate to.



<a id="nestedatt--configuration--subscriptions--management--vnet--iaas_subnets--web_tier"></a>
### Nested Schema for `configuration.subscriptions.management.vnet.iaas_subnets.web_tier`

Required:

- `ip_address_netnum` (Number) Netnum is a whole number that represent the order of the resulting subnet after increasing the bits with `newbits`. For example, if given a /24 and a newbits value of 2, the resulting subnet address will have length /26. There are 4 x /26 possible resulting subnets and netnum can choose which one by provinding `0`, `1`, `2` or `3`.
- `ip_address_newbits` (Number) Newbits is the number of additional bits with which to extend the Region's `ip_address_mask`. For example, if given a /24 and a newbits value of 2, the resulting subnet address will have length /26.

Optional:

- `delegation` (Attributes) Provides details to deleted the subnet to a supported Azure service. (see [below for nested schema](#nestedatt--configuration--subscriptions--management--vnet--iaas_subnets--web_tier--delegation))
- `service_endpoints` (List of String) The list of Service endpoints to associate with the subnet.

<a id="nestedatt--configuration--subscriptions--management--vnet--iaas_subnets--web_tier--delegation"></a>
### Nested Schema for `configuration.subscriptions.management.vnet.iaas_subnets.web_tier.delegation`

Required:

- `name` (String) A name for this delegation.
- `service` (String) The name of service to delegate to.

Optional:

- `actions` (List of String) A list of Actions which should be delegated. This list is specific to the service to delegate to.




<a id="nestedatt--configuration--subscriptions--management--vnet--paas_subnets"></a>
### Nested Schema for `configuration.subscriptions.management.vnet.paas_subnets`

Optional:

- `app_tier` (Attributes Map) Enables PaaS subnets for app tier services. The map keys CAN be on of: `aci`, `etc`. (see [below for nested schema](#nestedatt--configuration--subscriptions--management--vnet--paas_subnets--app_tier))
- `data_tier` (Attributes Map) Enables 1 PaaS subnet for data tier services. The map keys CAN be on of: `pgsql` and `sqlmi`. (see [below for nested schema](#nestedatt--configuration--subscriptions--management--vnet--paas_subnets--data_tier))
- `web_tier` (Attributes Map) Enables 1 PaaS subnet for web tier (internet facing) services. The map keys CAN be on of: `agw`. (see [below for nested schema](#nestedatt--configuration--subscriptions--management--vnet--paas_subnets--web_tier))

<a id="nestedatt--configuration--subscriptions--management--vnet--paas_subnets--app_tier"></a>
### Nested Schema for `configuration.subscriptions.management.vnet.paas_subnets.app_tier`

Required:

- `delegation` (Attributes) Provides details to deleted the subnet to a supported Azure service. (see [below for nested schema](#nestedatt--configuration--subscriptions--management--vnet--paas_subnets--app_tier--delegation))
- `ip_address_netnum` (Number) Netnum is a whole number that represent the order of the resulting subnet after increasing the bits with `newbits`. For example, if given a /24 and a newbits value of 2, the resulting subnet address will have length /26. There are 4 x /26 possible resulting subnets and netnum can choose which one by provinding `0`, `1`, `2` or `3`.
- `ip_address_newbits` (Number) Newbits is the number of additional bits with which to extend the Region's `ip_address_mask`. For example, if given a /24 and a newbits value of 2, the resulting subnet address will have length /26.

Optional:

- `service_endpoints` (List of String) The list of Service endpoints to associate with the subnet.

<a id="nestedatt--configuration--subscriptions--management--vnet--paas_subnets--app_tier--delegation"></a>
### Nested Schema for `configuration.subscriptions.management.vnet.paas_subnets.app_tier.delegation`

Required:

- `name` (String) A name for this delegation.
- `service` (String) The name of service to delegate to.

Optional:

- `actions` (List of String) A list of Actions which should be delegated. This list is specific to the service to delegate to.



<a id="nestedatt--configuration--subscriptions--management--vnet--paas_subnets--data_tier"></a>
### Nested Schema for `configuration.subscriptions.management.vnet.paas_subnets.data_tier`

Required:

- `delegation` (Attributes) Provides details to deleted the subnet to a supported Azure service. (see [below for nested schema](#nestedatt--configuration--subscriptions--management--vnet--paas_subnets--data_tier--delegation))
- `ip_address_netnum` (Number) Netnum is a whole number that represent the order of the resulting subnet after increasing the bits with `newbits`. For example, if given a /24 and a newbits value of 2, the resulting subnet address will have length /26. There are 4 x /26 possible resulting subnets and netnum can choose which one by provinding `0`, `1`, `2` or `3`.
- `ip_address_newbits` (Number) Newbits is the number of additional bits with which to extend the Region's `ip_address_mask`. For example, if given a /24 and a newbits value of 2, the resulting subnet address will have length /26.

Optional:

- `service_endpoints` (List of String) The list of Service endpoints to associate with the subnet.

<a id="nestedatt--configuration--subscriptions--management--vnet--paas_subnets--data_tier--delegation"></a>
### Nested Schema for `configuration.subscriptions.management.vnet.paas_subnets.data_tier.delegation`

Required:

- `name` (String) A name for this delegation.
- `service` (String) The name of service to delegate to.

Optional:

- `actions` (List of String) A list of Actions which should be delegated. This list is specific to the service to delegate to.



<a id="nestedatt--configuration--subscriptions--management--vnet--paas_subnets--web_tier"></a>
### Nested Schema for `configuration.subscriptions.management.vnet.paas_subnets.web_tier`

Required:

- `delegation` (Attributes) Provides details to deleted the subnet to a supported Azure service. (see [below for nested schema](#nestedatt--configuration--subscriptions--management--vnet--paas_subnets--web_tier--delegation))
- `ip_address_netnum` (Number) Netnum is a whole number that represent the order of the resulting subnet after increasing the bits with `newbits`. For example, if given a /24 and a newbits value of 2, the resulting subnet address will have length /26. There are 4 x /26 possible resulting subnets and netnum can choose which one by provinding `0`, `1`, `2` or `3`.
- `ip_address_newbits` (Number) Newbits is the number of additional bits with which to extend the Region's `ip_address_mask`. For example, if given a /24 and a newbits value of 2, the resulting subnet address will have length /26.

Optional:

- `service_endpoints` (List of String) The list of Service endpoints to associate with the subnet.

<a id="nestedatt--configuration--subscriptions--management--vnet--paas_subnets--web_tier--delegation"></a>
### Nested Schema for `configuration.subscriptions.management.vnet.paas_subnets.web_tier.delegation`

Required:

- `name` (String) A name for this delegation.
- `service` (String) The name of service to delegate to.

Optional:

- `actions` (List of String) A list of Actions which should be delegated. This list is specific to the service to delegate to.






<a id="nestedatt--configuration--subscriptions--security"></a>
### Nested Schema for `configuration.subscriptions.security`

Required:

- `abbreviation` (String) This abbreviation will be used to uniquily identify resources created in this subscription. Only applies to resources that require Azure global uniqueness.

Optional:

- `backups` (Attributes) Configuration settings for backups in this subscription. Defaults to {"recovery_services_vault":{"backup_policies":{"file_share":[{"frequency":{"daily":{"time":"23:00"},"hourly":<null>},"name":"daily","retention":{"daily":{"count":33},"monthly":<null>,"weekly":<null>,"yearly":<null>},"timezone":"UTC"},{"frequency":{"daily":{"time":"23:00"},"hourly":<null>},"name":"monthly","retention":{"daily":{"count":33},"monthly":{"count":13,"days":<null>,"include_last_days":<null>,"weekdays":["Sunday"],"weeks":["Last"]},"weekly":{"count":13,"weekdays":["Saturday"]},"yearly":<null>},"timezone":"UTC"},{"frequency":{"daily":{"time":"23:00"},"hourly":<null>},"name":"weekly","retention":{"daily":{"count":33},"monthly":<null>,"weekly":{"count":13,"weekdays":["Saturday"]},"yearly":<null>},"timezone":"UTC"},{"frequency":{"daily":{"time":"23:00"},"hourly":<null>},"name":"yearly","retention":{"daily":{"count":33},"monthly":{"count":13,"days":<null>,"include_last_days":<null>,"weekdays":["Sunday"],"weeks":["Last"]},"weekly":{"count":13,"weekdays":["Saturday"]},"yearly":{"count":7,"days":<null>,"include_last_days":<null>,"months":["January"],"weekdays":["Monday"],"weeks":["First"]}},"timezone":"UTC"}],"vm":[{"frequency":{"daily":{"time":"23:00"},"hourly":<null>,"weekly":<null>},"name":"daily","policy_type":{"v1":<null>,"v2":{"instant_restore_retention_days":7}},"retention":{"daily":{"count":33},"monthly":<null>,"weekly":<null>,"yearly":<null>},"tiering_policy":<null>,"timezone":"UTC"},{"frequency":{"daily":{"time":"23:00"},"hourly":<null>,"weekly":<null>},"name":"monthly","policy_type":{"v1":<null>,"v2":{"instant_restore_retention_days":7}},"retention":{"daily":{"count":33},"monthly":{"count":13,"days":<null>,"include_last_days":<null>,"weekdays":["Sunday"],"weeks":["Last"]},"weekly":{"count":5,"weekdays":["Saturday"]},"yearly":<null>},"tiering_policy":<null>,"timezone":"UTC"},{"frequency":{"daily":{"time":"23:00"},"hourly":<null>,"weekly":<null>},"name":"weekly","policy_type":{"v1":<null>,"v2":{"instant_restore_retention_days":7}},"retention":{"daily":{"count":33},"monthly":<null>,"weekly":{"count":5,"weekdays":["Saturday"]},"yearly":<null>},"tiering_policy":<null>,"timezone":"UTC"},{"frequency":{"daily":{"time":"23:00"},"hourly":<null>,"weekly":<null>},"name":"yearly","policy_type":{"v1":<null>,"v2":{"instant_restore_retention_days":7}},"retention":{"daily":{"count":33},"monthly":{"count":13,"days":<null>,"include_last_days":<null>,"weekdays":["Sunday"],"weeks":["Last"]},"weekly":{"count":5,"weekdays":["Saturday"]},"yearly":{"count":7,"days":<null>,"include_last_days":<null>,"months":["January"],"weekdays":["Monday"],"weeks":["First"]}},"tiering_policy":<null>,"timezone":"UTC"}]},"encryption":{"enabled":true,"infrastructure_encryption":false},"immutability":<null>,"monitoring":{"alerts_for_all_job_failures":true},"sku":"Standard","soft_delete":true,"storage_mode_type":"GeoRedundant","tags":<null>}} (see [below for nested schema](#nestedatt--configuration--subscriptions--security--backups))
- `budgets` (Attributes List) Provides a list of budget objects. (see [below for nested schema](#nestedatt--configuration--subscriptions--security--budgets))
- `keyvault` (Attributes) Azure KeyVault configuration details. (see [below for nested schema](#nestedatt--configuration--subscriptions--security--keyvault))
- `resource_groups_lock` (Attributes) Configures Azure Delete Lock at Resource Groups level. (see [below for nested schema](#nestedatt--configuration--subscriptions--security--resource_groups_lock))
- `vnet` (Attributes) Settings for customizing standard subnets and adding PaaS subnets. (see [below for nested schema](#nestedatt--configuration--subscriptions--security--vnet))

<a id="nestedatt--configuration--subscriptions--security--backups"></a>
### Nested Schema for `configuration.subscriptions.security.backups`

Optional:

- `recovery_services_vault` (Attributes) Configuration settings for Recovery Services Vault in this subscription. Defaults to `{"backup_policies":{"file_share":[{"frequency":{"daily":{"time":"23:00"},"hourly":<null>},"name":"daily","retention":{"daily":{"count":33},"monthly":<null>,"weekly":<null>,"yearly":<null>},"timezone":"UTC"},{"frequency":{"daily":{"time":"23:00"},"hourly":<null>},"name":"monthly","retention":{"daily":{"count":33},"monthly":{"count":13,"days":<null>,"include_last_days":<null>,"weekdays":["Sunday"],"weeks":["Last"]},"weekly":{"count":13,"weekdays":["Saturday"]},"yearly":<null>},"timezone":"UTC"},{"frequency":{"daily":{"time":"23:00"},"hourly":<null>},"name":"weekly","retention":{"daily":{"count":33},"monthly":<null>,"weekly":{"count":13,"weekdays":["Saturday"]},"yearly":<null>},"timezone":"UTC"},{"frequency":{"daily":{"time":"23:00"},"hourly":<null>},"name":"yearly","retention":{"daily":{"count":33},"monthly":{"count":13,"days":<null>,"include_last_days":<null>,"weekdays":["Sunday"],"weeks":["Last"]},"weekly":{"count":13,"weekdays":["Saturday"]},"yearly":{"count":7,"days":<null>,"include_last_days":<null>,"months":["January"],"weekdays":["Monday"],"weeks":["First"]}},"timezone":"UTC"}],"vm":[{"frequency":{"daily":{"time":"23:00"},"hourly":<null>,"weekly":<null>},"name":"daily","policy_type":{"v1":<null>,"v2":{"instant_restore_retention_days":7}},"retention":{"daily":{"count":33},"monthly":<null>,"weekly":<null>,"yearly":<null>},"tiering_policy":<null>,"timezone":"UTC"},{"frequency":{"daily":{"time":"23:00"},"hourly":<null>,"weekly":<null>},"name":"monthly","policy_type":{"v1":<null>,"v2":{"instant_restore_retention_days":7}},"retention":{"daily":{"count":33},"monthly":{"count":13,"days":<null>,"include_last_days":<null>,"weekdays":["Sunday"],"weeks":["Last"]},"weekly":{"count":5,"weekdays":["Saturday"]},"yearly":<null>},"tiering_policy":<null>,"timezone":"UTC"},{"frequency":{"daily":{"time":"23:00"},"hourly":<null>,"weekly":<null>},"name":"weekly","policy_type":{"v1":<null>,"v2":{"instant_restore_retention_days":7}},"retention":{"daily":{"count":33},"monthly":<null>,"weekly":{"count":5,"weekdays":["Saturday"]},"yearly":<null>},"tiering_policy":<null>,"timezone":"UTC"},{"frequency":{"daily":{"time":"23:00"},"hourly":<null>,"weekly":<null>},"name":"yearly","policy_type":{"v1":<null>,"v2":{"instant_restore_retention_days":7}},"retention":{"daily":{"count":33},"monthly":{"count":13,"days":<null>,"include_last_days":<null>,"weekdays":["Sunday"],"weeks":["Last"]},"weekly":{"count":5,"weekdays":["Saturday"]},"yearly":{"count":7,"days":<null>,"include_last_days":<null>,"months":["January"],"weekdays":["Monday"],"weeks":["First"]}},"tiering_policy":<null>,"timezone":"UTC"}]},"encryption":{"enabled":true,"infrastructure_encryption":false},"immutability":<null>,"monitoring":{"alerts_for_all_job_failures":true},"sku":"Standard","soft_delete":true,"storage_mode_type":"GeoRedundant","tags":<null>}`. (see [below for nested schema](#nestedatt--configuration--subscriptions--security--backups--recovery_services_vault))

<a id="nestedatt--configuration--subscriptions--security--backups--recovery_services_vault"></a>
### Nested Schema for `configuration.subscriptions.security.backups.recovery_services_vault`

Optional:

- `backup_policies` (Attributes) Backup policies to be created in this Recovery Services Vault. Defaults to `{"file_share":[{"frequency":{"daily":{"time":"23:00"},"hourly":<null>},"name":"daily","retention":{"daily":{"count":33},"monthly":<null>,"weekly":<null>,"yearly":<null>},"timezone":"UTC"},{"frequency":{"daily":{"time":"23:00"},"hourly":<null>},"name":"monthly","retention":{"daily":{"count":33},"monthly":{"count":13,"days":<null>,"include_last_days":<null>,"weekdays":["Sunday"],"weeks":["Last"]},"weekly":{"count":13,"weekdays":["Saturday"]},"yearly":<null>},"timezone":"UTC"},{"frequency":{"daily":{"time":"23:00"},"hourly":<null>},"name":"weekly","retention":{"daily":{"count":33},"monthly":<null>,"weekly":{"count":13,"weekdays":["Saturday"]},"yearly":<null>},"timezone":"UTC"},{"frequency":{"daily":{"time":"23:00"},"hourly":<null>},"name":"yearly","retention":{"daily":{"count":33},"monthly":{"count":13,"days":<null>,"include_last_days":<null>,"weekdays":["Sunday"],"weeks":["Last"]},"weekly":{"count":13,"weekdays":["Saturday"]},"yearly":{"count":7,"days":<null>,"include_last_days":<null>,"months":["January"],"weekdays":["Monday"],"weeks":["First"]}},"timezone":"UTC"}],"vm":[{"frequency":{"daily":{"time":"23:00"},"hourly":<null>,"weekly":<null>},"name":"daily","policy_type":{"v1":<null>,"v2":{"instant_restore_retention_days":7}},"retention":{"daily":{"count":33},"monthly":<null>,"weekly":<null>,"yearly":<null>},"tiering_policy":<null>,"timezone":"UTC"},{"frequency":{"daily":{"time":"23:00"},"hourly":<null>,"weekly":<null>},"name":"monthly","policy_type":{"v1":<null>,"v2":{"instant_restore_retention_days":7}},"retention":{"daily":{"count":33},"monthly":{"count":13,"days":<null>,"include_last_days":<null>,"weekdays":["Sunday"],"weeks":["Last"]},"weekly":{"count":5,"weekdays":["Saturday"]},"yearly":<null>},"tiering_policy":<null>,"timezone":"UTC"},{"frequency":{"daily":{"time":"23:00"},"hourly":<null>,"weekly":<null>},"name":"weekly","policy_type":{"v1":<null>,"v2":{"instant_restore_retention_days":7}},"retention":{"daily":{"count":33},"monthly":<null>,"weekly":{"count":5,"weekdays":["Saturday"]},"yearly":<null>},"tiering_policy":<null>,"timezone":"UTC"},{"frequency":{"daily":{"time":"23:00"},"hourly":<null>,"weekly":<null>},"name":"yearly","policy_type":{"v1":<null>,"v2":{"instant_restore_retention_days":7}},"retention":{"daily":{"count":33},"monthly":{"count":13,"days":<null>,"include_last_days":<null>,"weekdays":["Sunday"],"weeks":["Last"]},"weekly":{"count":5,"weekdays":["Saturday"]},"yearly":{"count":7,"days":<null>,"include_last_days":<null>,"months":["January"],"weekdays":["Monday"],"weeks":["First"]}},"tiering_policy":<null>,"timezone":"UTC"}]}`. (see [below for nested schema](#nestedatt--configuration--subscriptions--security--backups--recovery_services_vault--backup_policies))
- `encryption` (Attributes) Encryption configuration for the Recovery Services Vault. Defaults to `` (see [below for nested schema](#nestedatt--configuration--subscriptions--security--backups--recovery_services_vault--encryption))
- `immutability` (String) Immutability settings of vault. Possible values are `Locked`, `Unlocked` or `Disabled`.
!!! warning
    Once `immutability` is set to `Locked`, changing it to other values forces a new Recovery Services Vault to be created.<br>
- `monitoring` (Attributes) Monitoring configuration for the Recovery Services Vault. Defaults to `` (see [below for nested schema](#nestedatt--configuration--subscriptions--security--backups--recovery_services_vault--monitoring))
- `sku` (String) Sets the vault's SKU. Possible values are `Standard` or `RS0`. Defaults to `Standard`
- `soft_delete` (Boolean) Is soft delete enable for this Vault? Defaults to `true`.
- `storage_mode_type` (String) The storage type of the Recovery Services Vault. Possible values are `GeoRedundant`, `LocallyRedundant` or `ZoneRedundant`. Defaults to `GeoRedundant`.
!!! note
    If `storage_mode_type` is `GeoRedundant` and there are multiple regions defined in this subscription,    cross region restore will be enabled by default, otherwise it will be disabled.    Once cross region restore is enabled, changing it back to false forces a new Recovery Service Vault to be created.
<br>
- `tags` (Map of String) Key-value map of resource tags.

<a id="nestedatt--configuration--subscriptions--security--backups--recovery_services_vault--backup_policies"></a>
### Nested Schema for `configuration.subscriptions.security.backups.recovery_services_vault.backup_policies`

Optional:

- `file_share` (Attributes List) A list of file share backup policies to create. (see [below for nested schema](#nestedatt--configuration--subscriptions--security--backups--recovery_services_vault--backup_policies--file_share))
- `vm` (Attributes List) A list of VM backup policies to create. (see [below for nested schema](#nestedatt--configuration--subscriptions--security--backups--recovery_services_vault--backup_policies--vm))

<a id="nestedatt--configuration--subscriptions--security--backups--recovery_services_vault--backup_policies--file_share"></a>
### Nested Schema for `configuration.subscriptions.security.backups.recovery_services_vault.backup_policies.file_share`

Required:

- `name` (String) Backup policy name MUST be lowercase alphanumeric and dash, between 1 and 80 characters.
- `retention` (Attributes) Configures the policy retention. (see [below for nested schema](#nestedatt--configuration--subscriptions--security--backups--recovery_services_vault--backup_policies--file_share--retention))

Optional:

- `frequency` (Attributes) Sets the backup frequency. Exactly one of `daily` or `hourly` MUST be specified. (see [below for nested schema](#nestedatt--configuration--subscriptions--security--backups--recovery_services_vault--backup_policies--file_share--frequency))
- `timezone` (String) Specifies the Time Zone which should be used by the host pool and its associated resources for time based events, the possible values are defined [here](https://jackstromberg.com/2017/01/list-of-time-zones-consumed-by-azure/). Defaults to `UTC`.

<a id="nestedatt--configuration--subscriptions--security--backups--recovery_services_vault--backup_policies--file_share--retention"></a>
### Nested Schema for `configuration.subscriptions.security.backups.recovery_services_vault.backup_policies.file_share.retention`

Optional:

- `daily` (Attributes) Configures the policy daily retention. (see [below for nested schema](#nestedatt--configuration--subscriptions--security--backups--recovery_services_vault--backup_policies--file_share--retention--daily))
- `monthly` (Attributes) Configures the policy monthly retention. Either `weekdays` and `weeks` or `days` and `include_last_days` must be specified. (see [below for nested schema](#nestedatt--configuration--subscriptions--security--backups--recovery_services_vault--backup_policies--file_share--retention--monthly))
- `weekly` (Attributes) Configures the policy weekly retention. (see [below for nested schema](#nestedatt--configuration--subscriptions--security--backups--recovery_services_vault--backup_policies--file_share--retention--weekly))
- `yearly` (Attributes) Configures the policy yearly retention. (see [below for nested schema](#nestedatt--configuration--subscriptions--security--backups--recovery_services_vault--backup_policies--file_share--retention--yearly))

<a id="nestedatt--configuration--subscriptions--security--backups--recovery_services_vault--backup_policies--file_share--retention--daily"></a>
### Nested Schema for `configuration.subscriptions.security.backups.recovery_services_vault.backup_policies.file_share.retention.daily`

Optional:

- `count` (Number) The number of backups to keep. Must be between `1` and `200`. Defaults to `33`.


<a id="nestedatt--configuration--subscriptions--security--backups--recovery_services_vault--backup_policies--file_share--retention--monthly"></a>
### Nested Schema for `configuration.subscriptions.security.backups.recovery_services_vault.backup_policies.file_share.retention.monthly`

Optional:

- `count` (Number) The number of backups to keep. Must be between `1` and `120`. Defaults to `13`.
- `days` (Number) The days of the month to retain backups of. Must be between `1` and `31`. If specified, `include_last_days` MUST be specified as well and conflicts with `weekdays` and `weeks`.
- `include_last_days` (Boolean) Including the last day of the month. If specified, `days` MUST be specified as well and conflicts with `weekdays` and `weeks`.
- `weekdays` (List of String) The weekday backups to retain. Possible values are `Sunday`, `Monday`, `Tuesday`, `Wednesday`, `Thursday`, `Friday` or `Saturday`. If specified, `weeks` MUST be specified as well and conflicts with `days` and `include_last_days`.
- `weeks` (List of String) The weeks of the month to retain backups of. Possible values are `First`, `Second`, `Third`, `Fourth` or `Last`. If specified, `weekdays` MUST be specified as well and conflicts with `days` and `include_last_days`.


<a id="nestedatt--configuration--subscriptions--security--backups--recovery_services_vault--backup_policies--file_share--retention--weekly"></a>
### Nested Schema for `configuration.subscriptions.security.backups.recovery_services_vault.backup_policies.file_share.retention.weekly`

Optional:

- `count` (Number) The number of backups to keep. Must be between `1` and `200`. Defaults to `5`.
- `weekdays` (List of String) The weekday backups to retain. Possible values are `Sunday`, `Monday`, `Tuesday`, `Wednesday`, `Thursday`, `Friday` or `Saturday`.


<a id="nestedatt--configuration--subscriptions--security--backups--recovery_services_vault--backup_policies--file_share--retention--yearly"></a>
### Nested Schema for `configuration.subscriptions.security.backups.recovery_services_vault.backup_policies.file_share.retention.yearly`

Optional:

- `count` (Number) The number of backups to keep. Must be between `1` and `10`. Defaults to `7`.
- `days` (Number) The days of the month to retain backups of. Must be between `1` and `31`. If specified, `include_last_days` MUST be specified as well and conflicts with `weekdays` and `weeks`.
- `include_last_days` (Boolean) Including the last day of the month. If specified, `days` MUST be specified as well and conflicts with `weekdays` and `weeks`.
- `months` (List of String) The months of the year to retain backups of. Possible values are `January`, `February`, `March`, `April`, `May`, `June`, `July`, `August`, `September`, `October`, `November` and `December`. Defaults to `["January"]`.
- `weekdays` (List of String) The weekday backups to retain. Possible values are `Sunday`, `Monday`, `Tuesday`, `Wednesday`, `Thursday`, `Friday` or `Saturday`. If specified, `weeks` MUST be specified as well and conflicts with `days` and `include_last_days`.
- `weeks` (List of String) The weeks of the month to retain backups of. Possible values are `First`, `Second`, `Third`, `Fourth` or `Last`. If specified, `weekdays` MUST be specified as well and conflicts with `days` and `include_last_days`.



<a id="nestedatt--configuration--subscriptions--security--backups--recovery_services_vault--backup_policies--file_share--frequency"></a>
### Nested Schema for `configuration.subscriptions.security.backups.recovery_services_vault.backup_policies.file_share.frequency`

Optional:

- `daily` (Attributes) Sets the backup frequency to daily. Conflicts with `hourly`. (see [below for nested schema](#nestedatt--configuration--subscriptions--security--backups--recovery_services_vault--backup_policies--file_share--frequency--daily))
- `hourly` (Attributes) Sets the backup frequency to hourly. Conflicts with `daily`. (see [below for nested schema](#nestedatt--configuration--subscriptions--security--backups--recovery_services_vault--backup_policies--file_share--frequency--hourly))

<a id="nestedatt--configuration--subscriptions--security--backups--recovery_services_vault--backup_policies--file_share--frequency--daily"></a>
### Nested Schema for `configuration.subscriptions.security.backups.recovery_services_vault.backup_policies.file_share.frequency.daily`

Required:

- `time` (String) The time of day to perform the backup in 24-hour format. Times must be either on the hour or half hour (e.g. 12:00, 12:30, 13:00, etc.).


<a id="nestedatt--configuration--subscriptions--security--backups--recovery_services_vault--backup_policies--file_share--frequency--hourly"></a>
### Nested Schema for `configuration.subscriptions.security.backups.recovery_services_vault.backup_policies.file_share.frequency.hourly`

Required:

- `duration` (Number) Species the duration of the backup window in hours. MUST be a number between `4` and `24`. Details could be found [here](https://learn.microsoft.com/en-us/azure/backup/backup-azure-files-faq#what-does-the-duration-attribute-in-azure-files-backup-policy-signify-).
!!! note
    `duration` must be multiplier of `interval`<br>
- `interval` (Number) Specifies the interval at which backup needs to be triggered. Possible values are `4`, `6`, `8` and `12`.
- `time` (String) Specifies the start time of the hourly backup. The time format should be in 24-hour format. Times must be either on the hour or half hour (e.g. 12:00, 12:30, 13:00, etc.).




<a id="nestedatt--configuration--subscriptions--security--backups--recovery_services_vault--backup_policies--vm"></a>
### Nested Schema for `configuration.subscriptions.security.backups.recovery_services_vault.backup_policies.vm`

Required:

- `name` (String) Backup policy name MUST be lowercase alphanumeric and dash, between 1 and 80 characters.
- `retention` (Attributes) Configures the policy retention. (see [below for nested schema](#nestedatt--configuration--subscriptions--security--backups--recovery_services_vault--backup_policies--vm--retention))

Optional:

- `frequency` (Attributes) Sets the backup frequency. Exactly one of `daily`, `hourly` or `weekly` MUST be specified. (see [below for nested schema](#nestedatt--configuration--subscriptions--security--backups--recovery_services_vault--backup_policies--vm--frequency))
- `policy_type` (Attributes) Type of the Backup Policy. Possible values are `v1` or `v2`. Defaults to `{"v1":<null>,"v2":{"instant_restore_retention_days":7}}`.
!!! warning
    Changing this forces a new resource to be created.
<br> (see [below for nested schema](#nestedatt--configuration--subscriptions--security--backups--recovery_services_vault--backup_policies--vm--policy_type))
- `tiering_policy` (Attributes) Tiering policy configuration. (see [below for nested schema](#nestedatt--configuration--subscriptions--security--backups--recovery_services_vault--backup_policies--vm--tiering_policy))
- `timezone` (String) Specifies the Time Zone which should be used by the host pool and its associated resources for time based events, the possible values are defined [here](https://jackstromberg.com/2017/01/list-of-time-zones-consumed-by-azure/). Defaults to `UTC`.

<a id="nestedatt--configuration--subscriptions--security--backups--recovery_services_vault--backup_policies--vm--retention"></a>
### Nested Schema for `configuration.subscriptions.security.backups.recovery_services_vault.backup_policies.vm.retention`

Optional:

- `daily` (Attributes) Configures the policy daily retention. (see [below for nested schema](#nestedatt--configuration--subscriptions--security--backups--recovery_services_vault--backup_policies--vm--retention--daily))
- `monthly` (Attributes) Configures the policy monthly retention. Either `weekdays` and `weeks` or `days` and `include_last_days` must be specified. (see [below for nested schema](#nestedatt--configuration--subscriptions--security--backups--recovery_services_vault--backup_policies--vm--retention--monthly))
- `weekly` (Attributes) Configures the policy weekly retention. (see [below for nested schema](#nestedatt--configuration--subscriptions--security--backups--recovery_services_vault--backup_policies--vm--retention--weekly))
- `yearly` (Attributes) Configures the policy yearly retention. (see [below for nested schema](#nestedatt--configuration--subscriptions--security--backups--recovery_services_vault--backup_policies--vm--retention--yearly))

<a id="nestedatt--configuration--subscriptions--security--backups--recovery_services_vault--backup_policies--vm--retention--daily"></a>
### Nested Schema for `configuration.subscriptions.security.backups.recovery_services_vault.backup_policies.vm.retention.daily`

Optional:

- `count` (Number) The number of backups to keep. Must be between `7` and `9999`. Defaults to `33`.


<a id="nestedatt--configuration--subscriptions--security--backups--recovery_services_vault--backup_policies--vm--retention--monthly"></a>
### Nested Schema for `configuration.subscriptions.security.backups.recovery_services_vault.backup_policies.vm.retention.monthly`

Optional:

- `count` (Number) The number of backups to keep. Must be between `1` and `9999`. Defaults to `13`.
- `days` (Number) The days of the month to retain backups of. Must be between `1` and `31`. If specified, `include_last_days` MUST be specified as well and conflicts with `weekdays` and `weeks`.
- `include_last_days` (Boolean) Including the last day of the month. If specified, `days` MUST be specified as well and conflicts with `weekdays` and `weeks`.
- `weekdays` (List of String) The weekday backups to retain. Possible values are `Sunday`, `Monday`, `Tuesday`, `Wednesday`, `Thursday`, `Friday` or `Saturday`. If specified, `weeks` MUST be specified as well and conflicts with `days` and `include_last_days`.
- `weeks` (List of String) The weeks of the month to retain backups of. Possible values are `First`, `Second`, `Third`, `Fourth` or `Last`. If specified, `weekdays` MUST be specified as well and conflicts with `days` and `include_last_days`.


<a id="nestedatt--configuration--subscriptions--security--backups--recovery_services_vault--backup_policies--vm--retention--weekly"></a>
### Nested Schema for `configuration.subscriptions.security.backups.recovery_services_vault.backup_policies.vm.retention.weekly`

Optional:

- `count` (Number) The number of backups to keep. Must be between `1` and `9999`. Defaults to `5`.
- `weekdays` (List of String) The weekday backups to retain. Possible values are `Sunday`, `Monday`, `Tuesday`, `Wednesday`, `Thursday`, `Friday` or `Saturday`.


<a id="nestedatt--configuration--subscriptions--security--backups--recovery_services_vault--backup_policies--vm--retention--yearly"></a>
### Nested Schema for `configuration.subscriptions.security.backups.recovery_services_vault.backup_policies.vm.retention.yearly`

Optional:

- `count` (Number) The number of backups to keep. Must be between `1` and `9999`. Defaults to `7`.
- `days` (Number) The days of the month to retain backups of. Must be between `1` and `31`. If specified, `include_last_days` MUST be specified as well and conflicts with `weekdays` and `weeks`.
- `include_last_days` (Boolean) Including the last day of the month. If specified, `days` MUST be specified as well and conflicts with `weekdays` and `weeks`.
- `months` (List of String) The months of the year to retain backups of. Possible values are `January`, `February`, `March`, `April`, `May`, `June`, `July`, `August`, `September`, `October`, `November` and `December`. Defaults to `["January"]`.
- `weekdays` (List of String) The weekday backups to retain. Possible values are `Sunday`, `Monday`, `Tuesday`, `Wednesday`, `Thursday`, `Friday` or `Saturday`. If specified, `weeks` MUST be specified as well and conflicts with `days` and `include_last_days`.
- `weeks` (List of String) The weeks of the month to retain backups of. Possible values are `First`, `Second`, `Third`, `Fourth` or `Last`. If specified, `weekdays` MUST be specified as well and conflicts with `days` and `include_last_days`.



<a id="nestedatt--configuration--subscriptions--security--backups--recovery_services_vault--backup_policies--vm--frequency"></a>
### Nested Schema for `configuration.subscriptions.security.backups.recovery_services_vault.backup_policies.vm.frequency`

Optional:

- `daily` (Attributes) Sets the backup frequency to daily. Conflicts with `hourly` and `weekly`. (see [below for nested schema](#nestedatt--configuration--subscriptions--security--backups--recovery_services_vault--backup_policies--vm--frequency--daily))
- `hourly` (Attributes) Sets the backup frequency to hourly. Conflicts with `daily` and `weekly`. (see [below for nested schema](#nestedatt--configuration--subscriptions--security--backups--recovery_services_vault--backup_policies--vm--frequency--hourly))
- `weekly` (Attributes) Sets the backup frequency to daily. Conflicts with `daily` and `hourly`. (see [below for nested schema](#nestedatt--configuration--subscriptions--security--backups--recovery_services_vault--backup_policies--vm--frequency--weekly))

<a id="nestedatt--configuration--subscriptions--security--backups--recovery_services_vault--backup_policies--vm--frequency--daily"></a>
### Nested Schema for `configuration.subscriptions.security.backups.recovery_services_vault.backup_policies.vm.frequency.daily`

Required:

- `time` (String) The time of day to perform the backup in 24-hour format. Times must be either on the hour or half hour (e.g. 12:00, 12:30, 13:00, etc.).


<a id="nestedatt--configuration--subscriptions--security--backups--recovery_services_vault--backup_policies--vm--frequency--hourly"></a>
### Nested Schema for `configuration.subscriptions.security.backups.recovery_services_vault.backup_policies.vm.frequency.hourly`

Required:

- `duration` (Number) Species the duration of the backup window in hours. MUST be a number between `4` and `24`. Details could be found [here](https://learn.microsoft.com/en-us/azure/backup/backup-azure-files-faq#what-does-the-duration-attribute-in-azure-files-backup-policy-signify-).
!!! note
    `duration` must be multiplier of `interval`<br>
- `interval` (Number) Specifies the interval at which backup needs to be triggered. Possible values are `4`, `6`, `8` and `12`.
- `time` (String) Specifies the start time of the hourly backup. The time format should be in 24-hour format. Times must be either on the hour or half hour (e.g. 12:00, 12:30, 13:00, etc.).


<a id="nestedatt--configuration--subscriptions--security--backups--recovery_services_vault--backup_policies--vm--frequency--weekly"></a>
### Nested Schema for `configuration.subscriptions.security.backups.recovery_services_vault.backup_policies.vm.frequency.weekly`

Required:

- `time` (String) The time of day to perform the backup in 24-hour format. Times must be either on the hour or half hour (e.g. 12:00, 12:30, 13:00, etc.
- `weekdays` (List of String) The weekday backups to retain. Possible values are `Sunday`, `Monday`, `Tuesday`, `Wednesday`, `Thursday`, `Friday` or `Saturday`.



<a id="nestedatt--configuration--subscriptions--security--backups--recovery_services_vault--backup_policies--vm--policy_type"></a>
### Nested Schema for `configuration.subscriptions.security.backups.recovery_services_vault.backup_policies.vm.policy_type`

Optional:

- `v1` (Attributes) Backup Policy V1 configuration. Conflicts with V2. (see [below for nested schema](#nestedatt--configuration--subscriptions--security--backups--recovery_services_vault--backup_policies--vm--policy_type--v1))
- `v2` (Attributes) Backup Policy V2 (Enhanced Policy) configuration. Conflicts with V1. (see [below for nested schema](#nestedatt--configuration--subscriptions--security--backups--recovery_services_vault--backup_policies--vm--policy_type--v2))

<a id="nestedatt--configuration--subscriptions--security--backups--recovery_services_vault--backup_policies--vm--policy_type--v1"></a>
### Nested Schema for `configuration.subscriptions.security.backups.recovery_services_vault.backup_policies.vm.policy_type.v1`

Optional:

- `instant_restore_retention_days` (Number) Specifies the instant restore retention range in days. Possible values are between 1 and 5. Defaults to `5`.!!! note
    `instant_restore_retention_days` MUST be set to `5` if the backup frequency is set to `weekly`.
<br>


<a id="nestedatt--configuration--subscriptions--security--backups--recovery_services_vault--backup_policies--vm--policy_type--v2"></a>
### Nested Schema for `configuration.subscriptions.security.backups.recovery_services_vault.backup_policies.vm.policy_type.v2`

Optional:

- `instant_restore_retention_days` (Number) Specifies the instant restore retention range in days. Possible values are between 1 and 30. Defaults to `7`.!!! note
    `instant_restore_retention_days` MUST be set to `5` if the backup frequency is set to `weekly`.
<br>



<a id="nestedatt--configuration--subscriptions--security--backups--recovery_services_vault--backup_policies--vm--tiering_policy"></a>
### Nested Schema for `configuration.subscriptions.security.backups.recovery_services_vault.backup_policies.vm.tiering_policy`

Required:

- `archived_restore_point` (Attributes) Archived restore point configuration. (see [below for nested schema](#nestedatt--configuration--subscriptions--security--backups--recovery_services_vault--backup_policies--vm--tiering_policy--archived_restore_point))

<a id="nestedatt--configuration--subscriptions--security--backups--recovery_services_vault--backup_policies--vm--tiering_policy--archived_restore_point"></a>
### Nested Schema for `configuration.subscriptions.security.backups.recovery_services_vault.backup_policies.vm.tiering_policy.archived_restore_point`

Required:

- `mode` (String) The tiering mode to control automatic tiering of recovery points. Possible values are `TierAfter` or `TierRecommended`.

Optional:

- `duration` (Number) The number of days/weeks/months/years to retain backups in current tier before tiering.
- `duration_type` (String) The retention duration type. Possible values are `Days`, `Weeks`, `Months` or `Years`.





<a id="nestedatt--configuration--subscriptions--security--backups--recovery_services_vault--encryption"></a>
### Nested Schema for `configuration.subscriptions.security.backups.recovery_services_vault.encryption`

Optional:

- `enabled` (Boolean) Enabling/Disabling encryption state using the Key Vault key id created part of volocloud resource. Defaults to `true`
.!!! warning
    Once Encryption with your own key has been Enabled it's not possible to Disable it.<br>
- `infrastructure_encryption` (Boolean) Enabling/Disabling the Double Encryption state. Defaults to `false`
.!!! warning
    Once `infrastructure_encryption` has been set it's not possible to change it.<br>


<a id="nestedatt--configuration--subscriptions--security--backups--recovery_services_vault--monitoring"></a>
### Nested Schema for `configuration.subscriptions.security.backups.recovery_services_vault.monitoring`

Optional:

- `alerts_for_all_job_failures` (Boolean) Enabling/Disabling built-in Azure Monitor alerts for security scenarios and job failure scenarios. Defaults to `true`.




<a id="nestedatt--configuration--subscriptions--security--budgets"></a>
### Nested Schema for `configuration.subscriptions.security.budgets`

Required:

- `amount` (Number) The total amount of cost to track with the budget.
- `notifications` (Attributes List) One or more notification objects. (see [below for nested schema](#nestedatt--configuration--subscriptions--security--budgets--notifications))

Optional:

- `time_grain` (String) The time covered by a budget. Tracking of the amount will be reset based on the time grain. Possible values are `BillingAnnual`, `BillingMonth`, `BillingQuarter`, `Annually`, `Monthly` and `Quarterly`. Defaults to `Monthly`. Changing this forces a new resource to be created.

<a id="nestedatt--configuration--subscriptions--security--budgets--notifications"></a>
### Nested Schema for `configuration.subscriptions.security.budgets.notifications`

Required:

- `contact_emails` (List of String) Specifies a list of email addresses to send the budget notification to when the threshold is exceeded.
- `threshold` (Number) Threshold value associated with a notification. Notification is sent when the cost exceeded the threshold. It is always percent and has to be between 0 and 1000.

Optional:

- `operator` (String) The comparison operator for the notification. Possible values are `EqualTo`, `GreaterThan`, or `GreaterThanOrEqualTo`. Defaults to `EqualTo`.
- `threshold_type` (String) The type of threshold for the notification. This determines whether the notification is triggered by forecasted costs or actual costs. The allowed values are Actual and Forecasted. Default is Actual. Changing this forces a new resource to be created.



<a id="nestedatt--configuration--subscriptions--security--keyvault"></a>
### Nested Schema for `configuration.subscriptions.security.keyvault`

Optional:

- `purge_protection_enabled` (Boolean) Is Purge Protection enabled for this Key Vault? Defaults to true.
- `sku` (String) The Name of the SKU used for this Key Vault. Possible values are standard and premium. Defaults to standard.
- `soft_delete_retention_days` (Number) The number of days that items should be retained for once soft-deleted. This field can only be configured one time and cannot be updated. This value can be between 7 and 90 days. Defaults to 90.


<a id="nestedatt--configuration--subscriptions--security--resource_groups_lock"></a>
### Nested Schema for `configuration.subscriptions.security.resource_groups_lock`

Optional:

- `baseline` (Boolean) Boolean flag to enable/disable RG lock. Defaults to true.
- `rsv` (Boolean) Boolean flag to enable/disable RG lock. Defaults to false.


<a id="nestedatt--configuration--subscriptions--security--vnet"></a>
### Nested Schema for `configuration.subscriptions.security.vnet`

Optional:

- `iaas_subnets` (Attributes) Configure IaaS subnets. (see [below for nested schema](#nestedatt--configuration--subscriptions--security--vnet--iaas_subnets))
- `paas_subnets` (Attributes) Configure PaaS subnets. (see [below for nested schema](#nestedatt--configuration--subscriptions--security--vnet--paas_subnets))
- `vnet_link_to_private_dns_zones` (List of String) Provides a list of Azure Private DNS Zones to link to this VNET. The zones must be zones created by the volocloud provider: either PaaS private zones or custom private zones.

<a id="nestedatt--configuration--subscriptions--security--vnet--iaas_subnets"></a>
### Nested Schema for `configuration.subscriptions.security.vnet.iaas_subnets`

Optional:

- `app_tier` (Attributes) Enables 1 IaaS subnet for app tier services. (see [below for nested schema](#nestedatt--configuration--subscriptions--security--vnet--iaas_subnets--app_tier))
- `data_tier` (Attributes) Enables 1 IaaS subnet for data tier services. (see [below for nested schema](#nestedatt--configuration--subscriptions--security--vnet--iaas_subnets--data_tier))
- `web_tier` (Attributes) Enables 1 IaaS subnet for web tier (internet facing) services. (see [below for nested schema](#nestedatt--configuration--subscriptions--security--vnet--iaas_subnets--web_tier))

<a id="nestedatt--configuration--subscriptions--security--vnet--iaas_subnets--app_tier"></a>
### Nested Schema for `configuration.subscriptions.security.vnet.iaas_subnets.app_tier`

Required:

- `ip_address_netnum` (Number) Netnum is a whole number that represent the order of the resulting subnet after increasing the bits with `newbits`. For example, if given a /24 and a newbits value of 2, the resulting subnet address will have length /26. There are 4 x /26 possible resulting subnets and netnum can choose which one by provinding `0`, `1`, `2` or `3`.
- `ip_address_newbits` (Number) Newbits is the number of additional bits with which to extend the Region's `ip_address_mask`. For example, if given a /24 and a newbits value of 2, the resulting subnet address will have length /26.

Optional:

- `delegation` (Attributes) Provides details to deleted the subnet to a supported Azure service. (see [below for nested schema](#nestedatt--configuration--subscriptions--security--vnet--iaas_subnets--app_tier--delegation))
- `service_endpoints` (List of String) The list of Service endpoints to associate with the subnet.

<a id="nestedatt--configuration--subscriptions--security--vnet--iaas_subnets--app_tier--delegation"></a>
### Nested Schema for `configuration.subscriptions.security.vnet.iaas_subnets.app_tier.delegation`

Required:

- `name` (String) A name for this delegation.
- `service` (String) The name of service to delegate to.

Optional:

- `actions` (List of String) A list of Actions which should be delegated. This list is specific to the service to delegate to.



<a id="nestedatt--configuration--subscriptions--security--vnet--iaas_subnets--data_tier"></a>
### Nested Schema for `configuration.subscriptions.security.vnet.iaas_subnets.data_tier`

Required:

- `ip_address_netnum` (Number) Netnum is a whole number that represent the order of the resulting subnet after increasing the bits with `newbits`. For example, if given a /24 and a newbits value of 2, the resulting subnet address will have length /26. There are 4 x /26 possible resulting subnets and netnum can choose which one by provinding `0`, `1`, `2` or `3`.
- `ip_address_newbits` (Number) Newbits is the number of additional bits with which to extend the Region's `ip_address_mask`. For example, if given a /24 and a newbits value of 2, the resulting subnet address will have length /26.

Optional:

- `delegation` (Attributes) Provides details to deleted the subnet to a supported Azure service. (see [below for nested schema](#nestedatt--configuration--subscriptions--security--vnet--iaas_subnets--data_tier--delegation))
- `service_endpoints` (List of String) The list of Service endpoints to associate with the subnet.

<a id="nestedatt--configuration--subscriptions--security--vnet--iaas_subnets--data_tier--delegation"></a>
### Nested Schema for `configuration.subscriptions.security.vnet.iaas_subnets.data_tier.delegation`

Required:

- `name` (String) A name for this delegation.
- `service` (String) The name of service to delegate to.

Optional:

- `actions` (List of String) A list of Actions which should be delegated. This list is specific to the service to delegate to.



<a id="nestedatt--configuration--subscriptions--security--vnet--iaas_subnets--web_tier"></a>
### Nested Schema for `configuration.subscriptions.security.vnet.iaas_subnets.web_tier`

Required:

- `ip_address_netnum` (Number) Netnum is a whole number that represent the order of the resulting subnet after increasing the bits with `newbits`. For example, if given a /24 and a newbits value of 2, the resulting subnet address will have length /26. There are 4 x /26 possible resulting subnets and netnum can choose which one by provinding `0`, `1`, `2` or `3`.
- `ip_address_newbits` (Number) Newbits is the number of additional bits with which to extend the Region's `ip_address_mask`. For example, if given a /24 and a newbits value of 2, the resulting subnet address will have length /26.

Optional:

- `delegation` (Attributes) Provides details to deleted the subnet to a supported Azure service. (see [below for nested schema](#nestedatt--configuration--subscriptions--security--vnet--iaas_subnets--web_tier--delegation))
- `service_endpoints` (List of String) The list of Service endpoints to associate with the subnet.

<a id="nestedatt--configuration--subscriptions--security--vnet--iaas_subnets--web_tier--delegation"></a>
### Nested Schema for `configuration.subscriptions.security.vnet.iaas_subnets.web_tier.delegation`

Required:

- `name` (String) A name for this delegation.
- `service` (String) The name of service to delegate to.

Optional:

- `actions` (List of String) A list of Actions which should be delegated. This list is specific to the service to delegate to.




<a id="nestedatt--configuration--subscriptions--security--vnet--paas_subnets"></a>
### Nested Schema for `configuration.subscriptions.security.vnet.paas_subnets`

Optional:

- `app_tier` (Attributes Map) Enables PaaS subnets for app tier services. The map keys CAN be on of: `aci`, `etc`. (see [below for nested schema](#nestedatt--configuration--subscriptions--security--vnet--paas_subnets--app_tier))
- `data_tier` (Attributes Map) Enables 1 PaaS subnet for data tier services. The map keys CAN be on of: `pgsql` and `sqlmi`. (see [below for nested schema](#nestedatt--configuration--subscriptions--security--vnet--paas_subnets--data_tier))
- `web_tier` (Attributes Map) Enables 1 PaaS subnet for web tier (internet facing) services. The map keys CAN be on of: `agw`. (see [below for nested schema](#nestedatt--configuration--subscriptions--security--vnet--paas_subnets--web_tier))

<a id="nestedatt--configuration--subscriptions--security--vnet--paas_subnets--app_tier"></a>
### Nested Schema for `configuration.subscriptions.security.vnet.paas_subnets.app_tier`

Required:

- `delegation` (Attributes) Provides details to deleted the subnet to a supported Azure service. (see [below for nested schema](#nestedatt--configuration--subscriptions--security--vnet--paas_subnets--app_tier--delegation))
- `ip_address_netnum` (Number) Netnum is a whole number that represent the order of the resulting subnet after increasing the bits with `newbits`. For example, if given a /24 and a newbits value of 2, the resulting subnet address will have length /26. There are 4 x /26 possible resulting subnets and netnum can choose which one by provinding `0`, `1`, `2` or `3`.
- `ip_address_newbits` (Number) Newbits is the number of additional bits with which to extend the Region's `ip_address_mask`. For example, if given a /24 and a newbits value of 2, the resulting subnet address will have length /26.

Optional:

- `service_endpoints` (List of String) The list of Service endpoints to associate with the subnet.

<a id="nestedatt--configuration--subscriptions--security--vnet--paas_subnets--app_tier--delegation"></a>
### Nested Schema for `configuration.subscriptions.security.vnet.paas_subnets.app_tier.delegation`

Required:

- `name` (String) A name for this delegation.
- `service` (String) The name of service to delegate to.

Optional:

- `actions` (List of String) A list of Actions which should be delegated. This list is specific to the service to delegate to.



<a id="nestedatt--configuration--subscriptions--security--vnet--paas_subnets--data_tier"></a>
### Nested Schema for `configuration.subscriptions.security.vnet.paas_subnets.data_tier`

Required:

- `delegation` (Attributes) Provides details to deleted the subnet to a supported Azure service. (see [below for nested schema](#nestedatt--configuration--subscriptions--security--vnet--paas_subnets--data_tier--delegation))
- `ip_address_netnum` (Number) Netnum is a whole number that represent the order of the resulting subnet after increasing the bits with `newbits`. For example, if given a /24 and a newbits value of 2, the resulting subnet address will have length /26. There are 4 x /26 possible resulting subnets and netnum can choose which one by provinding `0`, `1`, `2` or `3`.
- `ip_address_newbits` (Number) Newbits is the number of additional bits with which to extend the Region's `ip_address_mask`. For example, if given a /24 and a newbits value of 2, the resulting subnet address will have length /26.

Optional:

- `service_endpoints` (List of String) The list of Service endpoints to associate with the subnet.

<a id="nestedatt--configuration--subscriptions--security--vnet--paas_subnets--data_tier--delegation"></a>
### Nested Schema for `configuration.subscriptions.security.vnet.paas_subnets.data_tier.delegation`

Required:

- `name` (String) A name for this delegation.
- `service` (String) The name of service to delegate to.

Optional:

- `actions` (List of String) A list of Actions which should be delegated. This list is specific to the service to delegate to.



<a id="nestedatt--configuration--subscriptions--security--vnet--paas_subnets--web_tier"></a>
### Nested Schema for `configuration.subscriptions.security.vnet.paas_subnets.web_tier`

Required:

- `delegation` (Attributes) Provides details to deleted the subnet to a supported Azure service. (see [below for nested schema](#nestedatt--configuration--subscriptions--security--vnet--paas_subnets--web_tier--delegation))
- `ip_address_netnum` (Number) Netnum is a whole number that represent the order of the resulting subnet after increasing the bits with `newbits`. For example, if given a /24 and a newbits value of 2, the resulting subnet address will have length /26. There are 4 x /26 possible resulting subnets and netnum can choose which one by provinding `0`, `1`, `2` or `3`.
- `ip_address_newbits` (Number) Newbits is the number of additional bits with which to extend the Region's `ip_address_mask`. For example, if given a /24 and a newbits value of 2, the resulting subnet address will have length /26.

Optional:

- `service_endpoints` (List of String) The list of Service endpoints to associate with the subnet.

<a id="nestedatt--configuration--subscriptions--security--vnet--paas_subnets--web_tier--delegation"></a>
### Nested Schema for `configuration.subscriptions.security.vnet.paas_subnets.web_tier.delegation`

Required:

- `name` (String) A name for this delegation.
- `service` (String) The name of service to delegate to.

Optional:

- `actions` (List of String) A list of Actions which should be delegated. This list is specific to the service to delegate to.







<a id="nestedatt--configuration--budgets"></a>
### Nested Schema for `configuration.budgets`

Optional:

- `landingzone_nonprod` (Attributes List) Provides a list of budget objects. (see [below for nested schema](#nestedatt--configuration--budgets--landingzone_nonprod))
- `landingzone_prod` (Attributes List) Provides a list of budget objects. (see [below for nested schema](#nestedatt--configuration--budgets--landingzone_prod))
- `platform` (Attributes List) Provides a list of budget objects. (see [below for nested schema](#nestedatt--configuration--budgets--platform))
- `root` (Attributes List) Provides a list of budget objects. (see [below for nested schema](#nestedatt--configuration--budgets--root))

<a id="nestedatt--configuration--budgets--landingzone_nonprod"></a>
### Nested Schema for `configuration.budgets.landingzone_nonprod`

Required:

- `amount` (Number) The total amount of cost to track with the budget.
- `notifications` (Attributes List) One or more notification objects. (see [below for nested schema](#nestedatt--configuration--budgets--landingzone_nonprod--notifications))

Optional:

- `time_grain` (String) The time covered by a budget. Tracking of the amount will be reset based on the time grain. Possible values are `BillingAnnual`, `BillingMonth`, `BillingQuarter`, `Annually`, `Monthly` and `Quarterly`. Defaults to `Monthly`. Changing this forces a new resource to be created.

<a id="nestedatt--configuration--budgets--landingzone_nonprod--notifications"></a>
### Nested Schema for `configuration.budgets.landingzone_nonprod.notifications`

Required:

- `contact_emails` (List of String) Specifies a list of email addresses to send the budget notification to when the threshold is exceeded.
- `threshold` (Number) Threshold value associated with a notification. Notification is sent when the cost exceeded the threshold. It is always percent and has to be between 0 and 1000.

Optional:

- `operator` (String) The comparison operator for the notification. Possible values are `EqualTo`, `GreaterThan`, or `GreaterThanOrEqualTo`. Defaults to `EqualTo`.
- `threshold_type` (String) The type of threshold for the notification. This determines whether the notification is triggered by forecasted costs or actual costs. The allowed values are Actual and Forecasted. Default is Actual. Changing this forces a new resource to be created.



<a id="nestedatt--configuration--budgets--landingzone_prod"></a>
### Nested Schema for `configuration.budgets.landingzone_prod`

Required:

- `amount` (Number) The total amount of cost to track with the budget.
- `notifications` (Attributes List) One or more notification objects. (see [below for nested schema](#nestedatt--configuration--budgets--landingzone_prod--notifications))

Optional:

- `time_grain` (String) The time covered by a budget. Tracking of the amount will be reset based on the time grain. Possible values are `BillingAnnual`, `BillingMonth`, `BillingQuarter`, `Annually`, `Monthly` and `Quarterly`. Defaults to `Monthly`. Changing this forces a new resource to be created.

<a id="nestedatt--configuration--budgets--landingzone_prod--notifications"></a>
### Nested Schema for `configuration.budgets.landingzone_prod.notifications`

Required:

- `contact_emails` (List of String) Specifies a list of email addresses to send the budget notification to when the threshold is exceeded.
- `threshold` (Number) Threshold value associated with a notification. Notification is sent when the cost exceeded the threshold. It is always percent and has to be between 0 and 1000.

Optional:

- `operator` (String) The comparison operator for the notification. Possible values are `EqualTo`, `GreaterThan`, or `GreaterThanOrEqualTo`. Defaults to `EqualTo`.
- `threshold_type` (String) The type of threshold for the notification. This determines whether the notification is triggered by forecasted costs or actual costs. The allowed values are Actual and Forecasted. Default is Actual. Changing this forces a new resource to be created.



<a id="nestedatt--configuration--budgets--platform"></a>
### Nested Schema for `configuration.budgets.platform`

Required:

- `amount` (Number) The total amount of cost to track with the budget.
- `notifications` (Attributes List) One or more notification objects. (see [below for nested schema](#nestedatt--configuration--budgets--platform--notifications))

Optional:

- `time_grain` (String) The time covered by a budget. Tracking of the amount will be reset based on the time grain. Possible values are `BillingAnnual`, `BillingMonth`, `BillingQuarter`, `Annually`, `Monthly` and `Quarterly`. Defaults to `Monthly`. Changing this forces a new resource to be created.

<a id="nestedatt--configuration--budgets--platform--notifications"></a>
### Nested Schema for `configuration.budgets.platform.notifications`

Required:

- `contact_emails` (List of String) Specifies a list of email addresses to send the budget notification to when the threshold is exceeded.
- `threshold` (Number) Threshold value associated with a notification. Notification is sent when the cost exceeded the threshold. It is always percent and has to be between 0 and 1000.

Optional:

- `operator` (String) The comparison operator for the notification. Possible values are `EqualTo`, `GreaterThan`, or `GreaterThanOrEqualTo`. Defaults to `EqualTo`.
- `threshold_type` (String) The type of threshold for the notification. This determines whether the notification is triggered by forecasted costs or actual costs. The allowed values are Actual and Forecasted. Default is Actual. Changing this forces a new resource to be created.



<a id="nestedatt--configuration--budgets--root"></a>
### Nested Schema for `configuration.budgets.root`

Required:

- `amount` (Number) The total amount of cost to track with the budget.
- `notifications` (Attributes List) One or more notification objects. (see [below for nested schema](#nestedatt--configuration--budgets--root--notifications))

Optional:

- `time_grain` (String) The time covered by a budget. Tracking of the amount will be reset based on the time grain. Possible values are `BillingAnnual`, `BillingMonth`, `BillingQuarter`, `Annually`, `Monthly` and `Quarterly`. Defaults to `Monthly`. Changing this forces a new resource to be created.

<a id="nestedatt--configuration--budgets--root--notifications"></a>
### Nested Schema for `configuration.budgets.root.notifications`

Required:

- `contact_emails` (List of String) Specifies a list of email addresses to send the budget notification to when the threshold is exceeded.
- `threshold` (Number) Threshold value associated with a notification. Notification is sent when the cost exceeded the threshold. It is always percent and has to be between 0 and 1000.

Optional:

- `operator` (String) The comparison operator for the notification. Possible values are `EqualTo`, `GreaterThan`, or `GreaterThanOrEqualTo`. Defaults to `EqualTo`.
- `threshold_type` (String) The type of threshold for the notification. This determines whether the notification is triggered by forecasted costs or actual costs. The allowed values are Actual and Forecasted. Default is Actual. Changing this forces a new resource to be created.





<a id="nestedatt--credentials"></a>
### Nested Schema for `credentials`

Required:

- `client_id` (String, Sensitive) Service Principal client ID configured in the target Azure tenant.
- `client_secret` (String, Sensitive) Service Principal client secret configured in the target Azure tenant.
- `subscription_id` (String, Sensitive) Target Azure Subscription ID.
- `tenant_id` (String, Sensitive) Target Azure tenant ID.

## Import

Import is supported using the following syntax:

```terraform
$ terraform import volocloud_tenancy_azure.example <resource ID>
```
!!! note

    The <resource ID> format is: "account_id:tenancy_id"
