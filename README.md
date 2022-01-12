# CipherTrust Terraform Provider

The CipherTrust Terraform Provider allows for the incorporation of CipherTrust Cloud Key Manager functionality into a 
CI/CD pipeline.

## Supported Clouds

- Amazon AWS
- Microsoft Azure
- Google Cloud
- Luna HSM
- Thales DSM

## CipherTrust Provider Initialization

The provider can be initialized either directly in the provider block of the terraform script or in a configuration 
file. If settings are specified in both locations, precedence will be given to those in the provider block.

### Provider block

```hcl
	provider "ciphertrust" {
	  address           = "https://34.207.194.87"
	  username          = "bob"
	  password          = "password"
	}
```

### Configuration file

CipherTrust provider will read configuration from ~/.ciphertrust/config.

```hcl
	address = https://34.207.194.87
	username = bob
	password = password
```

If a configuration file is used the provider can be initialized with an empty provider block.

```hcl
provider "ciphertrust" {)
```

Configuration items in the provider block have precedence over those in the configuration file.

## Environment Variables for AWS and Azure Clouds

The following environment variables can be used by the CipherTrust provider when creating connections to Azure and AWS.

### AWS

```hcl
AWS_ACCESS_KEY_ID
AWS_SECRET_ACCESS_KEY
```

### Azure

```hcl
ARM_CLIENT_ID
ARM_CLIENT_SECRET
ARM_TENANT_ID
ARM_SUBSCRIPTION_ID
```

## Argument Reference

### Required

- **address** (String) HTTPS URL of the CipherTrust instance.
- **username** (String) Username of a CipherTrust user.
- **password** (String, Sensitive) Password of the CipherTrust user.

### Optional

- **domain** (String) CipherTrust domain of the CipherTrust user.
- **log_file** (String) Log file name. Default is ctp.log.
- **log_level** (String) Log level. Options are: debug, info, warning, error and "off". Default is info.
- **no_ssl_verify** (Bool) Set to false to verify the server's certificate chain and host name. Default is true.
- **rest_api_timeout** (Number) CipherTrust rest api timeout in seconds. Default is 60.
- **azure_operation_timeout** (Number) Azure key operations can take time to complete. This specifies how long to wait for an operation to complete in seconds.  Default is 240.
- **hsm_operation_timeout** (Number) HSM connection opertions are not synchronous. This specifies how long to wait for an operation to complete in seconds. Default is 60.
