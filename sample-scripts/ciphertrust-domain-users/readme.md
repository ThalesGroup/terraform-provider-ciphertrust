# CipherTrust Manager Domain User Example

The scripts contained in the subdirectories illustrate how to create a domain and a domain user and how to then log in as that domain user.

'terraform apply' must be run in order of Step 1 to Step 3. 
'terraform destroy' must be run in the reverse order.

The scripts assume values for provider parameters not shown have been specified in a config file or in environment variables.

## Step 1 Creating a domain

In this step an administrator logs into the 'root' domain and creates a domain called 'testdomain'.

The 'domain' and 'auth_domain' parameters are empty in this step so the administrator will be logged into the 'root' domain.

In the script 'allow_user_management' is set to true so users can be created in 'testdomain;.

## Step 2 Creating a domain user

In this step the administrator will log in to 'testdomain' and create a user called 'testdomainuser'.

As the 'root' domain is the domain in which the administrator was created the value of 'auth_domain' value is 'root'.

The domain value is set to 'testdomain' so the administrator will be logged into that domain.

## Step 3 Domain user login.

In this step the user needs authenticate to 'testdomain' and logged into 'testdomain'.

Both 'domain' and 'auth_domain' values are set to 'testdomain'. 
