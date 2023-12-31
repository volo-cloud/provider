---
description: |-
  Use the Volo volocloud provider to interact with the Volo platform.

layout: ""
page_title: "Volocloud Provider"
hide:
  - toc
---

# Volocloud Provider

Use the Volo Volocloud provider to interact with the Volo platform. You must configure the provider with the proper credentials before you can use it.

Use the navigation to the left to read about the available resources.

~> **NOTE:** The Volocloud provider requires the use of Terraform 1.3.0 or later.

## Example Usage

Terraform 1.3.0 and later:

```terraform
terraform {
  required_providers {
    volocloud = {
      source  = "app.volo.co.nz/volo/volocloud"
      version = "0.1.0"
    }
  }
}

# Configure the Volocloud Provider
provider "volocloud" {
  account_id = "account id obtained during registration"
  api_key    = "api key obtained during registration"
  api_url    = "https://api.volocloud.volo.co.nz"
}
```

## Provider configuration

The Volocloud provider offers two ways to specify the required provider
configuration. The following methods are supported, in this order, and
explained below:

- Static
- Environment variables

### Static

Static configuration can be provided by adding an `account_id` and `api_url`
in-line in the Volocloud provider block:

Usage:

```terraform
provider "volocloud" {
  account_id = "csp-00000000-0000-0000-0000-000000000000"
  api_url    = "https://api.volocloud.volo.co.nz"
}
```

### Environment Variables

You can provide your configuration via the `VOLO_ACCOUNT_ID` and
`VOLO_API_URL`, environment variables, representing your Volo
Account ID and Volo Platform API URL, respectively.

```terraform
provider "volocloud" {}
```

Usage:

```sh
$ export VOLO_ACCOUNT_ID="csp-00000000-0000-0000-0000-000000000000"
$ export VOLO_API_URL="https://api.volocloud.volo.co.nz"
$ terraform plan
```

## Authentication

The Volocloud provider offers two ways of providing the API Key for
authentication. The following methods are supported, in this order, and
explained below:

- Static credentials
- Environment variables

### Static Credentials

!> **Warning:** Hard-coded credentials are not recommended in any Terraform
configuration and risks secret leakage should this file ever be committed to a
public version control system.

Static credentials can be provided by adding an `api_key`
in-line in the Volocloud provider block:

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

<!-- schema generated by tfplugindocs -->
## Schema

### Optional

- `account_id` (String, Sensitive) This is Volo Account ID. It must be provided, but it can also be sourced from the `VOLO_ACCOUNT_ID` environment variable.
- `api_key` (String, Sensitive) This is Volo API Key. It must be provided, but it can also be sourced from the `VOLO_API_KEY` environment variable.
- `api_url` (String) This is Volo API URL. It must be provided, but it can also be sourced from the `VOLO_API_URL` environment variable.
- `retain_resources_on_delete` (Boolean) This determines if actual resources inside target cloud service provider are being deleted in case volocloud resources are deleted. It defaults to true
