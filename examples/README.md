Using terraform-provider-ciphertrust

	Copy the terraform-provider-ciphertrust binary to the terraform plugin directory:

		~/.terraform.d/plugins/thales.com/terraform/ciphertrust/1.0.0/linux_amd64/

	To connect to AWS the following environment variables are required:

		export AWS_ACCESS_KEY_ID
		export AWS_SECRET_ACCESS_KEY

	To connect to Azure the following environment variables are required:

		export ARM_CLIENT_ID
		export ARM_CLIENT_SECRET
		export ARM_TENANT_ID
		export ARM_SUBSCRIPTION_ID

Provider Configuration

	CipherTrust provider configuration can be configured in the terraform script. For example:

		provider "ciphertrust" {
		  address			= "https://34.207.194.87"
		  username			= "bob"
		  password			= "password"
		  domain			= "root"
		  log_file			= "ctp.log"
		  log_level			= debug
		  no_ssl_verify		= false
		  rest_api_timeout	= 240
		  azure_opeation_timeout = 240
		  hsm_operation_timeout = 60
		}

	Only address, username, password are required, the others have default values as per the above example.

	All provider configuration can be set in a configuration file in ~/.ciphertrust/config.

		For example,
			  address = https://34.207.194.87
			  username = bob
			  password = password

		If the above are specified in the configuration file the provider can be initialized as:

			provider "ciphertrust" {)

	Settings in the provider block of a terraform script take precedence over tose in the configuration file.

Provider Logging

	By default logs will be written to ctp.log at the "info" level.

	The log file and log level can be set in the provider configuration block.

	Available log levels are debug, info, warning, error, off.

	For example:
		provider "ciphertrust" {
			log_file  = "azkeys.log"
			log_level = "debug"
		}

Running terraform-provider-ciphertrust examples

	Listing of the examples directory

	--- aws_keys
		--- create_keys
			--- assymmetric
				--- ec
					--- main.tf
					--- policy_vars.tf
			--- rsa
				--- main.tf
				--- policy_vars.tf
			--- symmetric
				--- main.tf
				--- policy_vars.tf
	--- import_key_material
		--- cm_key_material
			--- main.tf
		--- dsm_key_material
			--- dsm_vars.tf
			--- main.tf
	--- schedule_key_rotation
		--- cm_key_source
			--- main.tf
		--- dsm_key_source
			--- dsm_vars.tf
			--- main.tf
	--- upload_keys
		--- cm_key
			--- main.tf
		--- dsm_key
		--- dsm_vars.tf
		--- main.tf
	--- aws_s3_bucket
		--- main.tf
		--- modules
			--- connection
				--- main.tf
				--- outputs.tf
				--- variables.tf
			--- key
				--- main.tf
				--- outputs.tf
				--- variables.tf
			--- kms
				--- main.tf
				--- outputs.tf
				--- variables.tf
		--- output.tf
	--- azure_keys
		--- create_keys
			--- ec_key
				--- main.tf
				--- vault_vars.tf
			--- hsm_key
				--- main.tf
				--- rsa_key
				--- main.tf
				--- vault_vars.tf
		--- scheduled_key_rotation
			--- cm_key_source
				--- main.tf
				--- vault_vars.tf
			--- dsm_key_source
				--- dsm_vars.tf
	            --- main.tf
	            --- vault_vars.tf
			--- hsm_key_source
				--- hsm_vars.tf
				--- main.tf
				--- vault_vars.tf
		--- native-source
			--- main.tf
			--- vault_vars.tf
		--- upload_keys
			--- cm_key
				--- main.tf
				--- vault_vars.tf
			--- dsm_key
				--- dsm_vars.tf
				--- main.tf
				--- vault_vars.tf
			--- hsm-key
				--- hsm_vars.tf
				--- main.tf
				--- vault_vars.tf
			--- pfx_certificate
				--- main.tf
				--- pfx_vars.tf
				--- testcert.pfx
				--- vault_vars.tf
		--- azure_storage_account
			--- main.tf
			--- modules
				--- connection
					--- main.tf
					--- outputs.tf
					--- variables.tf
				--- key
					--- main.tf
					--- outputs.tf
					--- variables.tf
				--- vault
					--- main.tf
					--- outputs.tf
					--- variables.tf
			--- output.tf
			--- variables.tf
		--- connections
			--- aws
				--- main.tf
			--- azure
				--- main.tf
				--- vault_vars.tf
			--- dsm
				--- dsm_vars.tf
				--- main.tf
			--- hsm-luna
				--- hsm_vars.tf
				--- main.tf
		--- server_certs
			--- dsm-server.pem
			--- hsm-server.pem


	To run any of the following examples change directory to the folder that contains main.tf

		If the any of the following files exist in the directory edit as appropriate
			vault_vars.tf
				Input variables for creating Azure vaults
			policy_vars.tf
				Input variables specifying AWS key policy
			dsm_vars.tf
				Input variables specifying DSM information
			hsm_vars.tf
				Input variables specifying HSM information

		Run terraform init
			https://www.terraform.io/docs/cli/commands/init.html
			Only needs to be run once in a directory containing main.tf

		Run terraform plan (optional step)
			https://www.terraform.io/docs/cli/commands/plan.html

		Run terraform apply [-auto-approve]
			https://www.terraform.io/docs/cli/commands/apply.html
			Run again to update the resource
			Note: Not all input can be updated.

		Run terraform refresh (optional step)
			https://www.terraform.io/docs/cli/commands/refresh.html

		Run terraform destroy [-auto-approve]
			NOTE: Run terraform destroy even if terraform apply returned an error
			NOTE: Always run terraform before running another example
			https://www.terraform.io/docs/cli/commands/destroy.html

	Other usesful terraform commands:

		To view the provider schema:
			Run terraform providers schema [-json]

		To standardize the format of the terraform scripts:
			Run terraform fmt [-recursive]
