---
# generated by https://github.com/hashicorp/terraform-plugin-docs
page_title: "CipherTrust Provider"
subcategory: ""
description: |-
  The CipherTrust provider can be used configure a CipherTrust instance or cluster or a CipherTrust Data Security Platform as a Service (CDSPaaS) and subsequently manage cloud resources.
---

# CipherTrust Provider

Use the navigation to the left to read about the available resources.

[Sample scripts](https://github.com/ThalesGroup/terraform-provider-ciphertrust/tree/main/sample-scripts) allow you to easily create CipherTrust Manager resources for your cloud and includes some practical examples of using the CipherTrust provider with other cloud providers. 

## Supported Clouds

## Public Clouds
- AWS
- Azure
- Google Cloud

### AWS Deployment
To deploy a Virtual CipherTrust Manager from AWS, you must supply the Amazon Machine Image (AMI), available on the AWS Marketplace or through the Thales Cloud Provisioning System. The cluster example in dev_examples demonstrates launching CipherTrust Manager images from AWS.

### Azure Deployment
1. List the available versions with `Get-AzVMImage -location eastus2 -PublisherName thalesdiscplusainc1596561677238 -Offer cm_k170v -sku ciphertrust_manager`.

2. Obtain image information for a particular version with `az vm image show --location eastus2 --urn thalesdiscplusainc1596561677238:cm_k170v:ciphertrust_manager:<desired-version>`. Under `plan`, obtain the required values for `name`, `product` and `publisher`.

3. Consult [azurerm provider documentation](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/linux_virtual_machine) for details on creating a plan to launch a Linux Virtual Machine with the azurerm provider.

### Google Cloud Deployment

1. List the available CipherTrust Manager versions with `gcloud compute images list --no-standard-images --project=thales-cpl-public`. CipherTrust Manager image names start with the prefix `k170v`. Copy the `NAME` of the image you would like to deploy.

2. Consult [Google Cloud Platform provider documentation](https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/compute_instance) for details on launching a Virtual Machine image with the GCP provider.

## Thales Devices
The following devices can be used to create keys for the above public clouds.
- CipherTrust Manager
- DSM
- HSM Luna

## Provider Initialization

All CipherTrust Provider parameters can be provided in :
 - The provider block of the terraform script
 - A configuration file ~/.ciphertrust/config

CipherTrust authentication parameters can also be provided as environment variables.

The following table illustrates which parameters can be provided as environment variables or in the configuration file.

| Provider Parameter   | Environment Variable | Config File | Required  | Default Value              |
|:---------------------|:---------------------|:------------|:----------|:---------------------------|
| address              | CM_ADDRESS           | address     | Yes       | N/A                        |
| username             | CM_USERNAME          | username    | Yes       | N/A                        |
| password             | CM_PASSWORD          | password    | Yes       | N/A                        |
| domain               | CM_DOMAIN            | domain      | No        | Empty string (root domain) |
| auth_domain          | CM_AUTH_DOMAIN       | auth_domain | No        | Empty string (root domain) |
| remaining parameters | no                   | yes         | No        | N/A                        |

The order of precedence when determining the value of a provider parameter: 
1. Provider Block
2. Environment Variable
3. Configuration File

## Provider Block 

### For CipherTrust Manager

To authenticate to and log in to the root domain:
```terraform
provider "ciphertrust" {
  address  = "cm-address"
  username = "cm-username"
  password = "cm-password"
}

```
To authenticate to and log in to a domain other than root: 

```terraform
provider "ciphertrust" {
  address      = "cm-address"
  username     = "cm-username"
  password     = "cm-password"
  auth_domain  = "users-auth-domain" 
}
```

To authenticate to a domain but log in to a different domain:

```terraform
provider "ciphertrust" {
  address      = "cm-address"
  username     = "cm-username"
  password     = "cm-password"
  auth_domain  = "users-auth-domain"
  domain       = "a-different-domain"
}
```

### For CipherTrust Data Security Platform as a Service (CDSPaaS)

```terraform
provider "ciphertrust" {
  address     = "cdsp-address"
  username    = "cdsp-tenant-username"
  password    = "cdsp-tenant-password"
  auth_domain = "cdsp-tenant-name"
}
```
## Configuration File

All provider parameters can be read from the configuration file.

The configuration file is ~/.ciphertrust/config. For example:

```terraform
  address = cm-address
  username = cm-username
  password = cm-password
```
If authentication values exist in the configuration file the provider block can be:

```terraform
provider "ciphertrust" {}
 ```

### Environment variables

Some provider parameters can be specified in environment variables.

```bash
export CM_USERNAME=cm-username
export CM_PASSWORD=cm-password
export CM_AUTH_DOMAIN=cm-auth-domain
export CM_DOMAIN=cm-domain
```

If environment variables required for authentication exist the provider block can be:

```terraform
provider "ciphertrust" {}
 ```

<!-- schema generated by tfplugindocs -->
## Schema

### Required

- **username** (String) Username of a CipherTrust user. username can be set in the provider block, via the CM_USERNAME environment variable or in ~/.ciphertrust/config
- **password** (String, Sensitive) Password of a CipherTrust user. password can be set in the provider block, via the CM_PASSWORD environment variable or in ~/.ciphertrust/config

### Optional

- **address** (String) HTTPS URL of the CipherTrust instance. address can be set in the provider block, via the CM_ADDRESS environment variable or in ~/.ciphertrust/config. An address need not be provided when creating a cluster of CipherTrust instances.
- **auth_domain** (String) CipherTrust authentication domain of the user. This is the domain where the user was created. auth_domain can be set in the provider block, via the CM_AUTH_DOMAIN environment variable or in ~/.ciphertrust/config. Default is the empty string (root domain).
- **domain** (String) CipherTrust domain to log in to. domain can be set in the provider block, via the CM_DOMAIN environment variable or in ~/.ciphertrust/config. Default is the root domain.
- **no_ssl_verify** (Boolean) Set to false to verify the server's certificate chain and host name. no_ssl_verify can be set in the provider block or in ~/.ciphertrust/config. Default is true.
- **rest_api_timeout** (Number) CipherTrust rest api timeout in seconds. rest_api_timeout can be set in the provider block or in ~/.ciphertrust/config. Default is 60.

## Supported resource types

The following table illustrates which resource types are supported in CipherTrust Manager and CipherTrust Data Security Platform as a Service(CDSPaaS).
| Resource Type                    | CipherTrust Manager | CDSPaaS |
|:---------------------------------|:--------------------|:--------|
| ciphertrust_cluster              | yes                 | no      |
| ciphertrust_cm_key               | yes                 | yes     |
| ciphertrust_cte_client           | yes                 | no      |
| ciphertrust_cte_guardpoint       | yes                 | no      |
| ciphertrust_cte_policies         | yes                 | no      |
| ciphertrust_domain               | yes                 | no      |
| ciphertrust_groups               | yes                 | yes     |
| ciphertrust_interface            | yes                 | no      |
| ciphertrust_license              | yes                 | no      |
| ciphertrust_log_forwarder        | yes                 | no      |
| ciphertrust_ntp                  | yes                 | no      |
| ciphertrust_password_policy      | yes                 | no      |
| ciphertrust_policies             | yes                 | no      |
| ciphertrust_policy_attachments   | yes                 | no      |
| ciphertrust_property             | yes                 | no      |
| ciphertrust_proxy                | yes                 | no      |
| ciphertrust_scheduler            | yes                 | yes     |
| ciphertrust_syslog               | yes                 | no      |
| ciphertrust_user                 | yes                 | yes     |
