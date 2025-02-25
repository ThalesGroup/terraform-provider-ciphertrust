package provider

import (
	"context"
	"fmt"
	"os"

	"github.com/google/uuid"

	cm "github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/cm"
	common "github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	connections "github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/connections"
	cte "github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/cte"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// Ensure the implementation satisfies the expected interfaces.
var (
	_ provider.Provider = &ciphertrustProvider{}
)

// New is a helper function to simplify provider server and testing implementation.
func New(version string) func() provider.Provider {
	return func() provider.Provider {
		return &ciphertrustProvider{
			version: version,
		}
	}
}

// ciphertrustProvider is the provider implementation.
type ciphertrustProvider struct {
	// version is set to the provider version on release, "dev" when the
	// provider is built and ran locally, and "test" when running acceptance
	// testing.
	version string
}

type ciphertrustProviderModel struct {
	Username             types.String `tfsdk:"username"`
	Password             types.String `tfsdk:"password"`
	Domain               types.String `tfsdk:"domain"`
	Bootstrap            types.String `tfsdk:"bootstrap"`
	AuthDomain           types.String `tfsdk:"auth_domain"`
	InsecureSkipVerify   types.Bool   `tfsdk:"no_ssl_verify"`
	RestOperationTimeout types.Int64  `tfsdk:"rest_api_timeout"`
	Address              types.String `tfsdk:"address"`
}

const (
	providerDescWithDefault         = "%s can be set in the provider block or in ~/.ciphertrust/config. Default is %s."
	providerDescNoDefaultWithEnvVar = "%s can be set in the provider block, via the %s environment variable or in ~/.ciphertrust/config"
	defaultRestAPITimeout           = "60"
	//providerDescWithDefaultAndEnvVar = "%s can be set in the provider block, via the %s environment variable or in ~/.ciphertrust/config. Default is %s."
)

// Metadata returns the provider type name.
func (p *ciphertrustProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "ciphertrust"
	resp.Version = p.version
}

// Schema defines the provider-level schema for configuration data.
func (p *ciphertrustProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"address": schema.StringAttribute{
				Optional:    true,
				Description: "HTTPS URL of the CipherTrust instance. An address need not be provided when creating a cluster of CipherTrust instances. " + fmt.Sprintf(providerDescNoDefaultWithEnvVar, "address", "CM_ADDRESS"),
			},
			"username": schema.StringAttribute{
				Optional:    true,
				Description: "Username of a CipherTrust user. " + fmt.Sprintf(providerDescNoDefaultWithEnvVar, "username", "CM_USERNAME"),
			},
			"password": schema.StringAttribute{
				Optional:    true,
				Sensitive:   true,
				Description: "Password of a CipherTrust user. " + fmt.Sprintf(providerDescNoDefaultWithEnvVar, "password", "CM_PASSWORD"),
			},
			"bootstrap": schema.StringAttribute{
				Optional:    true,
				Sensitive:   true,
				Description: "Is it a bootstrap operation. " + fmt.Sprintf(providerDescNoDefaultWithEnvVar, "bootstrap", "no"),
			},
			"auth_domain": schema.StringAttribute{
				Optional:    true,
				Description: "CipherTrust authentication domain of the user. This is the domain where the user was created. " + fmt.Sprintf(providerDescNoDefaultWithEnvVar+". Default is the empty string (root domain).", "auth_domain", "CM_AUTH_DOMAIN"),
			},
			"domain": schema.StringAttribute{
				Optional:    true,
				Description: "CipherTrust domain to log in to. " + fmt.Sprintf(providerDescNoDefaultWithEnvVar+". Default is the empty string (root domain).", "domain", "CM_DOMAIN"),
			},
			"no_ssl_verify": &schema.BoolAttribute{
				Optional:    true,
				Description: "Set to false to verify the server's certificate chain and host name. " + fmt.Sprintf(providerDescWithDefault, "no_ssl_verify", "true"),
			},
			"rest_api_timeout": schema.Int64Attribute{
				Optional:    true,
				Description: "CipherTrust rest api timeout in seconds. " + fmt.Sprintf(providerDescWithDefault, "rest_api_timeout", defaultRestAPITimeout),
			},
		},
	}
}

// Configure prepares a CipherTrust API client for data sources and resources.
func (p *ciphertrustProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[provider.go -> Configure]["+id+"]")

	// Retrieve provider data from configuration
	var config ciphertrustProviderModel
	diags := req.Config.Get(ctx, &config)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// If practitioner provided a configuration value for any of the
	// attributes, it must be a known value.

	if config.Address.IsUnknown() {
		resp.Diagnostics.AddAttributeError(
			path.Root("address"),
			"Unknown CipherTrust IP/FQDN",
			"The provider cannot create the CipherTrust API client as there is an unknown configuration value for the host address. "+
				"Either target apply the source of the value first, set the value statically in the configuration, or use the CIPHERTRUST_ADDRESS environment variable.",
		)
	}

	if config.Username.IsUnknown() {
		resp.Diagnostics.AddAttributeError(
			path.Root("username"),
			"Unknown CipherTrust API Username",
			"The provider cannot create the CipherTrust API client as there is an unknown configuration value for the CipherTrust API username. "+
				"Either target apply the source of the value first, set the value statically in the configuration, or use the CIPHERTRUST_USERNAME environment variable.",
		)
	}

	if config.Password.IsUnknown() {
		resp.Diagnostics.AddAttributeError(
			path.Root("password"),
			"Unknown CipherTrust API Password",
			"The provider cannot create the CipherTrust API client as there is an unknown configuration value for the CipherTrust API password. "+
				"Either target apply the source of the value first, set the value statically in the configuration, or use the CIPHERTRUST_PASSWORD environment variable.",
		)
	}

	if resp.Diagnostics.HasError() {
		return
	}

	// Default values to environment variables, but override
	// with Terraform configuration value if set.

	address := os.Getenv("CIPHERTRUST_ADDRESS")
	username := os.Getenv("CIPHERTRUST_USERNAME")
	password := os.Getenv("CIPHERTRUST_PASSWORD")
	bootstrap := os.Getenv("BOOTSTRAP")
	domain := os.Getenv("CIPHERTRUST_DOMAIN")
	auth_domain := os.Getenv("CIPHERTRUST_AUTH_DOMAIN")

	if !config.Address.IsNull() {
		address = config.Address.ValueString()
	}

	if !config.Username.IsNull() {
		username = config.Username.ValueString()
	}

	if !config.Password.IsNull() {
		password = config.Password.ValueString()
	}

	if !config.Bootstrap.IsNull() {
		bootstrap = config.Bootstrap.ValueString()
	}

	if !config.Domain.IsNull() {
		domain = config.Domain.ValueString()
	}

	if !config.AuthDomain.IsNull() {
		auth_domain = config.AuthDomain.ValueString()
	}

	// If any of the expected configurations are missing, return
	// errors with provider-specific guidance.
	if bootstrap == "no" {
		if address == "" {
			resp.Diagnostics.AddAttributeError(
				path.Root("address"),
				"Missing CipherTrust API IP/FQDN",
				"The provider cannot create the CipherTrust API client as there is a missing or empty value for the CipherTrust API host. "+
					"Set the host value in the configuration or use the CIPHERTRUST_ADDRESS environment variable. "+
					"If either is already set, ensure the value is not empty.",
			)
		}

		if username == "" {
			resp.Diagnostics.AddAttributeError(
				path.Root("username"),
				"Missing CipherTrust API Username",
				"The provider cannot create the CipherTrust API client as there is a missing or empty value for the CipherTrust API username. "+
					"Set the username value in the configuration or use the CIPHERTRUST_USERNAME environment variable. "+
					"If either is already set, ensure the value is not empty.",
			)
		}

		if password == "" {
			resp.Diagnostics.AddAttributeError(
				path.Root("password"),
				"Missing CipherTrust API Password",
				"The provider cannot create the CipherTrust API client as there is a missing or empty value for the CipherTrust API password. "+
					"Set the password value in the configuration or use the CIPHERTRUST_PASSWORD environment variable. "+
					"If either is already set, ensure the value is not empty.",
			)
		}

		if resp.Diagnostics.HasError() {
			return
		}
	}

	ctx = tflog.SetField(ctx, "cm_host", address)
	ctx = tflog.SetField(ctx, "cm_username", username)
	ctx = tflog.SetField(ctx, "cm_password", password)
	ctx = tflog.SetField(ctx, "bootstrap", bootstrap)
	ctx = tflog.MaskFieldValuesWithFieldKeys(ctx, "cm_password")

	tflog.Debug(ctx, "Creating CM client")

	if bootstrap == "no" {
		// Create a new CipherTrust client using the configuration values
		client, err := common.NewClient(ctx, id, &address, &auth_domain, &domain, &username, &password)
		if err != nil {
			resp.Diagnostics.AddError(
				"Unable to Create CipherTrust API Client",
				"An unexpected error occurred when creating the CipherTrust API client. "+
					"If the error is not clear, please contact the provider developers.\n\n"+
					"CipherTrust Client Error: "+err.Error(),
			)
			return
		}

		resp.DataSourceData = client
		resp.ResourceData = client
	} else if bootstrap == "yes" {
		client, err := common.NewCMClientBoot(ctx, id, &address)
		if err != nil {
			resp.Diagnostics.AddError(
				"Unable to Create CipherTrust API Client",
				"An unexpected error occurred when creating the CipherTrust API client. "+
					"If the error is not clear, please contact the provider developers.\n\n"+
					"CipherTrust Client Error: "+err.Error(),
			)
			return
		}

		resp.DataSourceData = client
		resp.ResourceData = client
	} else {
		resp.Diagnostics.AddError(
			"Unable to Create CipherTrust API Client",
			"Error Message: bootstrap value can be either yes or no, No other value is allowed!",
		)
		return
	}
}

// DataSources defines the data sources implemented in the provider.
func (p *ciphertrustProvider) DataSources(_ context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{
		cm.NewDataSourceUsers,
		cm.NewDataSourceKeys,
		cm.NewDataSourceGroups,
		cte.NewDataSourceCTEUserSets,
		cte.NewDataSourceCTEResourceSets,
		cte.NewDataSourceCTEProcessSets,
		cte.NewDataSourceCTEPolicyDataTXRule,
		cte.NewDataSourceCTEPolicyIDTKeyRule,
		cte.NewDataSourceCTEPolicyKeyRule,
		cte.NewDataSourceCTEPolicyLDTKeyRule,
		cte.NewDataSourceCTEPolicySecurityRule,
		cte.NewDataSourceCTEPolicySignatureRule,
		cte.NewDataSourceCTEProfiles,
		cm.NewDataSourceRegTokens,
		cte.NewDataSourceCTEClients,
		cm.NewDataSourceCertificateAuthorities,
		connections.NewDataSourceScpConnection,
		cm.NewDataSourcePrometheus,
		connections.NewDataSourceGCPConnection,
		connections.NewDataSourceAzureConnection,
		cm.NewDataSourceScheduler,
		connections.NewDataSourceAWSConnection,
	}
}

// Resources defines the resources implemented in the provider.
func (p *ciphertrustProvider) Resources(_ context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		cm.NewResourceCMUser,
		cm.NewResourceCMKey,
		cm.NewResourceCMGroup,
		cte.NewResourceCTEProcessSet,
		cte.NewResourceCTEResourceSet,
		cte.NewResourceCTEUserSet,
		cte.NewResourceCTESignatureSet,
		cte.NewResourceCTEPolicy,
		cte.NewResourceCTEClient,
		cte.NewResourceCTEPolicyDataTXRule,
		cte.NewResourceCTEPolicyIDTKeyRule,
		cte.NewResourceCTEPolicyKeyRule,
		cte.NewResourceCTEPolicyLDTKeyRule,
		cte.NewResourceCTEPolicySecurityRule,
		cte.NewResourceCTEPolicySignatureRule,
		cte.NewResourceCTEProfile,
		cm.NewResourceCMRegToken,
		cm.NewResourceCMSSHKey,
		cm.NewResourceCMPwdChange,
		cte.NewResourceCTEClientGP,
		cte.NewResourceCTEClientGroup,
		cte.NewResourceCTECSIGroup,
		cte.NewResourceLDTGroupCommSvc,
		connections.NewResourceCCKMAWSConnection,
		cm.NewResourceHSMRootOfTrustServer,
		connections.NewResourceCMScpConnection,
		cm.NewResourceCMCluster,
		cm.NewResourceCMInterface,
		cm.NewResourceCMLicense,
		cm.NewResourceCMNTP,
		cm.NewResourceCMTrialLicense,
		cm.NewResourceCMPrometheus,
		connections.NewResourceGCPConnection,
		connections.NewResourceAzureConnection,
		cm.NewResourceScheduler,
		cm.NewResourceCMDomain,
		cm.NewResourceCMLogForwarders,
		cm.NewResourceCMPasswordPolicy,
		cm.NewResourceCMPolicy,
		cm.NewResourceCMPolicyAttachment,
		cm.NewResourceCMProperty,
		cm.NewResourceCMProxy,
		cm.NewResourceCMSyslog,
	}
}
