# CipherTrust Manager Provider Examples

This directory contains examples of creating various CipherTrust resources with
Terraform. 

The examples each have their own README containing details on what the example does and how to run them.

Refer to the [online documentation](https://registry.terraform.io/providers/ThalesGroup/ciphertrust/latest/docs) for details on each resource. 

## Configuring Terraform Variables

All scripts require cloud credentials and most scripts use variables that require your input.

It's possible to configure all variables to your values for all scripts or you can simply edit the *var.tf files in the directory of the script you wish to run.

### Configure for All Example Scripts

The executable shell scripts in this directory make it easy to configure the same variables in all *var.tf files at the same time.

Carefully edit the shell scripts that pertain to the clouds and resources you wish to create then execute the script.

If you are not going to use a cloud\resource\parameter there is no need to provide values.

### Configure for Specific Scripts Only

Each directory containing a main.tf script that requires variables also has one or more *.var files in which the variables can be configured.   

## Connection Scripts

Examples that create connections between CipherTrust Manager and the cloud for:
- AWS
- Azure
- Google Cloud
- DSM
- HSM Luna

## Cloud-Key Scripts

Examples that create a variety of cloud keys in a variety of ways for:
- AWS
- Azure
- Google Cloud

Examples that schedule key rotation using a variety of key sources for:
- AWS
- Azure
- Google Cloud
 
Examples that schedule key synchronization for:
- AWS
- Azure
- Google Cloud
 
Example that create the following services:
- Google EKM Endpoint
- Google Workspace

## Practical-Examples Scripts

This directory contains real-world examples of using the CipherTrust Manager provider in conjunction with a cloud provider to do something practical.
