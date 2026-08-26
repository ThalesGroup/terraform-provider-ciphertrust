package provider

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/hashicorp/go-hclog"

	aws "github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/cckm/aws"
	azure "github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/cckm/azure"
	oci "github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/cckm/oci"
	cm "github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/cm"
	common "github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	connections "github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/connections"
	cte "github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/cte"
	"github.com/google/uuid"
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

const (
	defaultAwsOperationTimeout = 480
	defaultOciOperationTimeout = 480
	defaultReplicationDelay    = 100
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

	// logFileHandle is the *os.File backing the provider-specific log writer.
	// hclog does not own or close the writer, so we track it here to close it
	// before opening a new one on repeated Configure calls (e.g. plan + apply).
	logFileHandle *os.File
}

type ciphertrustProviderModel struct {
	Username             types.String `tfsdk:"username"`
	Password             types.String `tfsdk:"password"`
	Domain               types.String `tfsdk:"domain"`
	Bootstrap            types.String `tfsdk:"bootstrap"`
	AuthDomain           types.String `tfsdk:"auth_domain"`
	Tenant               types.String `tfsdk:"tenant"`
	InsecureSkipVerify   types.Bool   `tfsdk:"no_ssl_verify"`
	CACert               types.String `tfsdk:"ca_cert"`
	RestOperationTimeout types.Int64  `tfsdk:"rest_api_timeout"`
	Address              types.String `tfsdk:"address"`
	AwsOperationTimeout  types.Int64  `tfsdk:"aws_operation_timeout"`
	OCIOperationTimeout  types.Int64  `tfsdk:"oci_operation_timeout"`
	ReplicationDelayMS   types.Int64  `tfsdk:"replication_delay_ms"`
	LogFile              types.String `tfsdk:"log_file"`
	LogLevel             types.String `tfsdk:"log_level"`
}

const (
	providerDescWithDefault         = "%s can be set in the provider block or in ~/.ciphertrust/config. Default is %v."
	providerDescNoDefaultWithEnvVar = "%s can be set in the provider block, via the %s environment variable or in ~/.ciphertrust/config"
	providerDescDefaultWithEnvVar   = "%s can be set in the provider block, via the %s environment variable or in ~/.ciphertrust/config. Default is %v."
	defaultRestAPITimeout           = "180"
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
				Description: "HTTPS URL of the CipherTrust instance. An address need not be provided when creating a cluster of CipherTrust instances. " + fmt.Sprintf(providerDescNoDefaultWithEnvVar, "address", "CIPHERTRUST_ADDRESS"),
			},
			"username": schema.StringAttribute{
				Optional:    true,
				Description: "Username of a CipherTrust user. " + fmt.Sprintf(providerDescNoDefaultWithEnvVar, "username", "CIPHERTRUST_USERNAME"),
			},
			"password": schema.StringAttribute{
				Optional:    true,
				Sensitive:   true,
				Description: "Password of a CipherTrust user. " + fmt.Sprintf(providerDescNoDefaultWithEnvVar, "password", "CIPHERTRUST_PASSWORD"),
			},
			"bootstrap": schema.StringAttribute{
				Optional:    true,
				Description: "Is it a bootstrap operation. " + fmt.Sprintf(providerDescNoDefaultWithEnvVar, "bootstrap", "BOOTSTRAP"),
			},
			"auth_domain": schema.StringAttribute{
				Optional:    true,
				Description: "CipherTrust authentication domain of the user. This is the domain where the user was created. " + fmt.Sprintf(providerDescNoDefaultWithEnvVar+". Default is the empty string (root domain).", "auth_domain", "CIPHERTRUST_AUTH_DOMAIN"),
			},
			"domain": schema.StringAttribute{
				Optional:    true,
				Description: "CipherTrust domain to log in to. " + fmt.Sprintf(providerDescNoDefaultWithEnvVar+". Default is the empty string (root domain).", "domain", "CIPHERTRUST_DOMAIN"),
			},
			"tenant": schema.StringAttribute{
				Optional: true,
				Description: "CDSPaaS tenant name (e.g. \"acme\") or tenant path (e.g. \"acme/eng/team\"). " +
					"Setting this opts the provider into the CDSPaaS authentication path; leave unset for on-prem CipherTrust Manager. " +
					fmt.Sprintf(providerDescNoDefaultWithEnvVar, "tenant", "CIPHERTRUST_TENANT"),
			},
			"no_ssl_verify": &schema.BoolAttribute{
				Optional: true,
				Description: "Disable TLS certificate chain and hostname verification when set to true. " +
					"**WARNING:** disabling certificate verification exposes connections to man-in-the-middle attacks " +
					"and should only be used for local development or testing — never in production. " +
					"Set to false (the default) to enforce certificate validation; supply a custom CA bundle via " +
					"`ca_cert` for private PKI or air-gapped environments. " +
					fmt.Sprintf(providerDescWithDefault, "no_ssl_verify", "false"),
			},
			"ca_cert": schema.StringAttribute{
				Optional: true,
				Description: "Path to a PEM-encoded CA certificate bundle used to validate the CipherTrust server's TLS certificate. " +
					"Use this for private PKI, internally-issued certificates, or air-gapped environments where the certificate chain is " +
					"not in the system trust store. The file may contain one or more concatenated PEM certificates. " +
					fmt.Sprintf(providerDescNoDefaultWithEnvVar, "ca_cert", "CIPHERTRUST_CA_CERT"),
			},
			"rest_api_timeout": schema.Int64Attribute{
				Optional:    true,
				Description: "CipherTrust rest api timeout in seconds. " + fmt.Sprintf(providerDescWithDefault, "rest_api_timeout", defaultRestAPITimeout),
			},
			"aws_operation_timeout": schema.Int64Attribute{
				Optional:    true,
				Description: "Some AWS key operations, for example, replication, can take some time to complete. This specifies how long to wait for an operation to complete in seconds. " + fmt.Sprintf(providerDescWithDefault, "aws_operation_timeout", defaultAwsOperationTimeout),
			},
			"oci_operation_timeout": schema.Int64Attribute{
				Optional:    true,
				Description: "Some OCI key operations can take some time to complete. This specifies how long to wait for an operation to complete in seconds. " + fmt.Sprintf(providerDescWithDefault, "oci_operation_timeout", defaultOciOperationTimeout),
			},
			"replication_delay_ms": schema.Int64Attribute{
				Optional:    true,
				Description: "In the case of a CipherTrust Manager cluster behind a load balancer a small delay after creating CipherTrust Manager resources may be required to allow for replication to other cluster instances. " + fmt.Sprintf(providerDescDefaultWithEnvVar, "replication_delay_ms", "CIPHERTRUST_REPLICATION_DELAY", defaultReplicationDelay),
			},
			"log_file": schema.StringAttribute{
				Optional:    true,
				Description: "Path to the provider log file. Provider logs are written separately from Terraform debug logs. " + fmt.Sprintf(providerDescWithDefault, "log_file", "ctp.log"),
			},
			"log_level": schema.StringAttribute{
				Optional:    true,
				Description: "Logging level for the provider log file. " + fmt.Sprintf(providerDescWithDefault, "log_level", "info") + " Options: debug, info, warn, error, off.",
			},
		},
	}
}

// openProviderLog opens (or, when logLevel is "off", skips opening) the
// provider log file. It returns the logger, the underlying *os.File (nil when
// level is "off"), and any error. The caller owns the returned file handle and
// must close it when no longer needed.
//
// The file is always created with mode 0600 so that sensitive API details
// recorded at debug level are not world-readable on multi-user systems.
func openProviderLog(logFile, logLevel string) (hclog.Logger, *os.File, error) {
	if strings.EqualFold(logLevel, "off") {
		return hclog.NewNullLogger(), nil, nil
	}
	f, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return nil, nil, err
	}
	logger := hclog.New(&hclog.LoggerOptions{
		Name:   "ciphertrust",
		Level:  hclog.LevelFromString(logLevel),
		Output: f,
	})
	return logger, f, nil
}

// Configure prepares a CipherTrust API client for data sources and resources.
func (p *ciphertrustProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[provider.go -> Configure]["+id+"]")

	// Retrieve provider data from configuration
	var config ciphertrustProviderModel
	var address string
	var username string
	var password string
	var domain string
	var bootstrap string
	var auth_domain string
	var tenant string
	var no_ssl_verify bool
	var ca_cert string
	var rest_api_timeout int64
	var aws_operation_timeout = int64(defaultAwsOperationTimeout)
	var oci_operation_timeout = int64(defaultOciOperationTimeout)
	var replication_delay_ms = int64(defaultReplicationDelay)
	var log_file = "ctp.log"
	var log_level = "info"

	diags := req.Config.Get(ctx, &config)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	//Some default values
	bootstrap = "no"
	// Secure-by-default: TLS certificate verification is ENABLED unless the
	// user explicitly opts out via no_ssl_verify=true (mitigates CWE-295).
	no_ssl_verify = false
	rest_api_timeout = 180

	//First read from the config file
	homeDir, _ := os.UserHomeDir()
	configFileName := filepath.Join(homeDir, ".ciphertrust/config")

	// Validate config file exists, is not a symlink, and has secure permissions
	if info, err := os.Lstat(configFileName); err == nil {
		// 1. Symlink validation to prevent symlink redirect attacks
		if info.Mode()&os.ModeSymlink != 0 {
			resp.Diagnostics.AddError(
				"Unsecured Configuration File detected",
				fmt.Sprintf("The configuration file %q is a symbolic link. Symbolic links are prohibited to prevent symlink attacks.", configFileName),
			)
			return
		}

		// 2. Permission validation (Must not be group or world readable/writable/executable, i.e., perm & 0077 != 0)
		if info.Mode().Perm()&0077 != 0 {
			resp.Diagnostics.AddError(
				"Unsecured Configuration File detected",
				fmt.Sprintf("The configuration file %q has insecure permissions (%04o). It must be restricted to user-only access (e.g., 0600 or 0400) to prevent credentials leakage to other users on the system.", configFileName, info.Mode().Perm()),
			)
			return
		}

		// Read and parse the secure config file
		if file, err := os.Open(configFileName); err == nil {
			defer file.Close()
			scanner := bufio.NewScanner(file)
			for scanner.Scan() {
				line := scanner.Text()
				parts := strings.SplitN(line, "=", 2)
				if len(parts) != 2 {
					continue
				}

				key := strings.TrimSpace(parts[0])
				value := strings.TrimSpace(parts[1])

				var parseErr error
				switch key {
				case "address":
					address = value
				case "username":
					username = value
				case "password":
					password = value
				case "bootstrap":
					bootstrap = value
				case "domain":
					domain = value
				case "auth_domain":
					auth_domain = value
				case "tenant":
					tenant = value
				case "no_ssl_verify":
					no_ssl_verify, parseErr = strconv.ParseBool(value)
					if parseErr != nil {
						resp.Diagnostics.AddError(
							"Invalid provider configuration in config file",
							fmt.Sprintf("Failed to parse %s=%q as boolean: %s", key, value, parseErr.Error()),
						)
					}
				case "ca_cert":
					ca_cert = value
				case "rest_api_timeout":
					rest_api_timeout, parseErr = strconv.ParseInt(value, 10, 64)
					if parseErr != nil {
						resp.Diagnostics.AddError(
							"Invalid provider configuration in config file",
							fmt.Sprintf("Failed to parse %s=%q as integer: %s", key, value, parseErr.Error()),
						)
					}
				case "aws_operation_timeout":
					aws_operation_timeout, parseErr = strconv.ParseInt(value, 10, 64)
					if parseErr != nil {
						resp.Diagnostics.AddError(
							"Invalid provider configuration in config file",
							fmt.Sprintf("Failed to parse %s=%q as integer: %s", key, value, parseErr.Error()),
						)
					}
				case "oci_operation_timeout":
					oci_operation_timeout, parseErr = strconv.ParseInt(value, 10, 64)
					if parseErr != nil {
						resp.Diagnostics.AddError(
							"Invalid provider configuration in config file",
							fmt.Sprintf("Failed to parse %s=%q as integer: %s", key, value, parseErr.Error()),
						)
					}
				case "replication_delay_ms":
					replication_delay_ms, parseErr = strconv.ParseInt(value, 10, 64)
					if parseErr != nil {
						resp.Diagnostics.AddError(
							"Invalid provider configuration in config file",
							fmt.Sprintf("Failed to parse %s=%q as integer: %s", key, value, parseErr.Error()),
						)
					}
				case "log_file":
					log_file = value
				case "log_level":
					log_level = value
				}
			}
		}
	}

	// If environment vars are found, make them higher priority
	addressEnvVal, addressEnvExists := os.LookupEnv("CIPHERTRUST_ADDRESS")
	if addressEnvExists {
		address = addressEnvVal
	}
	usernameEnvVal, usernameEnvExists := os.LookupEnv("CIPHERTRUST_USERNAME")
	if usernameEnvExists {
		username = usernameEnvVal
	}
	passwordEnvVal, passwordEnvExists := os.LookupEnv("CIPHERTRUST_PASSWORD")
	if passwordEnvExists {
		password = passwordEnvVal
	}
	bootstrapEnvVal, bootstrapEnvExists := os.LookupEnv("BOOTSTRAP")
	if bootstrapEnvExists {
		bootstrap = bootstrapEnvVal
	}
	domainEnvVal, domainEnvExists := os.LookupEnv("CIPHERTRUST_DOMAIN")
	if domainEnvExists {
		domain = domainEnvVal
	}
	authDomainEnvVal, authDomainEnvExists := os.LookupEnv("CIPHERTRUST_AUTH_DOMAIN")
	if authDomainEnvExists {
		auth_domain = authDomainEnvVal
	}
	tenantEnvVal, tenantEnvExists := os.LookupEnv("CIPHERTRUST_TENANT")
	if tenantEnvExists {
		tenant = tenantEnvVal
	}
	noSSLVerifyEnvVal, noSSLVerifyEnvExists := os.LookupEnv("NO_SSL_VERIFY")
	if noSSLVerifyEnvExists {
		var parseErr error
		no_ssl_verify, parseErr = strconv.ParseBool(noSSLVerifyEnvVal)
		if parseErr != nil {
			resp.Diagnostics.AddError(
				"Invalid environment variable configuration",
				fmt.Sprintf("Failed to parse environment variable NO_SSL_VERIFY=%q as boolean: %s", noSSLVerifyEnvVal, parseErr.Error()),
			)
		}
	}
	caCertEnvVal, caCertEnvExists := os.LookupEnv("CIPHERTRUST_CA_CERT")
	if caCertEnvExists {
		ca_cert = caCertEnvVal
	}
	restAPITimeoutEnvVal, restAPITimeoutEnvExists := os.LookupEnv("REST_API_TIMEOUT")
	if restAPITimeoutEnvExists {
		var parseErr error
		rest_api_timeout, parseErr = strconv.ParseInt(restAPITimeoutEnvVal, 10, 64)
		if parseErr != nil {
			resp.Diagnostics.AddError(
				"Invalid environment variable configuration",
				fmt.Sprintf("Failed to parse environment variable REST_API_TIMEOUT=%q as integer: %s", restAPITimeoutEnvVal, parseErr.Error()),
			)
		}
	}
	replicationDelayEnvVal, replicationDelayEnvExists := os.LookupEnv("CIPHERTRUST_REPLICATION_DELAY")
	if replicationDelayEnvExists {
		var parseErr error
		replication_delay_ms, parseErr = strconv.ParseInt(replicationDelayEnvVal, 10, 64)
		if parseErr != nil {
			resp.Diagnostics.AddError(
				"Invalid environment variable configuration",
				fmt.Sprintf("Failed to parse environment variable CIPHERTRUST_REPLICATION_DELAY=%q as integer: %s", replicationDelayEnvVal, parseErr.Error()),
			)
		}
	}

	if resp.Diagnostics.HasError() {
		return
	}

	// Finally if the provider block has values, make that highest priority
	if !config.LogFile.IsNull() && config.LogFile.ValueString() != "" {
		log_file = config.LogFile.ValueString()
	}
	if !config.LogLevel.IsNull() && config.LogLevel.ValueString() != "" {
		log_level = config.LogLevel.ValueString()
	}

	// Close any file handle left open by a previous Configure call (e.g.
	// terraform plan followed by terraform apply, or repeated acceptance-test
	// runs). hclog does not own the writer lifecycle so we must do this here.
	if p.logFileHandle != nil {
		_ = p.logFileHandle.Close()
		p.logFileHandle = nil
	}
	providerLogger, logFH, logErr := openProviderLog(log_file, log_level)
	if logErr != nil {
		resp.Diagnostics.AddError(
			"Failed to open provider log file",
			fmt.Sprintf("Could not open log file %q: %s", log_file, logErr.Error()),
		)
		return
	}
	p.logFileHandle = logFH
	if logFH != nil {
		providerLogger.Info("CipherTrust provider initialising", "log_level", log_level, "log_file", log_file)
	}

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

	if !config.Tenant.IsNull() {
		tenant = config.Tenant.ValueString()
	}

	if !config.InsecureSkipVerify.IsNull() {
		no_ssl_verify = config.InsecureSkipVerify.ValueBool()
	}

	if !config.CACert.IsNull() {
		ca_cert = config.CACert.ValueString()
	}

	if !config.RestOperationTimeout.IsNull() {
		rest_api_timeout = config.RestOperationTimeout.ValueInt64()
	}

	if !config.AwsOperationTimeout.IsNull() {
		aws_operation_timeout = config.AwsOperationTimeout.ValueInt64()
	}

	if !config.OCIOperationTimeout.IsNull() {
		oci_operation_timeout = config.OCIOperationTimeout.ValueInt64()
	}

	if !config.ReplicationDelayMS.IsNull() {
		replication_delay_ms = config.ReplicationDelayMS.ValueInt64()
	}

	// Surface the insecure mode loudly — it should only be used in test
	// environments, never in production (CWE-295).
	if no_ssl_verify {
		resp.Diagnostics.AddAttributeWarning(
			path.Root("no_ssl_verify"),
			"TLS certificate verification is disabled",
			"`no_ssl_verify = true` disables TLS certificate chain and hostname validation for all "+
				"CipherTrust API calls. This is intended for local development and testing only and "+
				"must not be used in production. For private PKI or air-gapped environments supply a "+
				"custom CA bundle via `ca_cert` instead.",
		)
	}

	tlsOpts := common.TLSOptions{
		InsecureSkipVerify: no_ssl_verify,
		CACertPath:         ca_cert,
	}

	// auth_domain_path (sent when tenant is set) supersedes auth_domain server-side.
	// Warn the user so they don't think their auth_domain value is being honoured.
	if tenant != "" && auth_domain != "" {
		resp.Diagnostics.AddAttributeWarning(
			path.Root("auth_domain"),
			"auth_domain is ignored when tenant is set",
			"Both \"tenant\" and \"auth_domain\" are configured. The CDSPaaS "+
				"authentication path uses auth_domain_path (derived from tenant), "+
				"which supersedes auth_domain. Remove auth_domain to silence this warning.",
		)
	}

	// If any of the expected configurations are missing, return
	// errors with provider-specific guidance.
	if bootstrap == "no" {
		// If not bootstrap, we want address, username, and password should be there
		// Else address is mandatory
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
	} else {
		if address == "" {
			resp.Diagnostics.AddAttributeError(
				path.Root("address"),
				"Missing CipherTrust API IP/FQDN",
				"The provider cannot create the CipherTrust API client as there is a missing or empty value for the CipherTrust API host. "+
					"Set the host value in the configuration or use the CIPHERTRUST_ADDRESS environment variable. "+
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
		client, err := common.NewClient(ctx, id, &address, &auth_domain, &domain, &username, &password, &tenant, tlsOpts, rest_api_timeout)
		if err != nil {
			resp.Diagnostics.AddError(
				"Unable to Create CipherTrust API Client",
				"An unexpected error occurred when creating the CipherTrust API client. "+
					"If the error is not clear, please contact the provider developers.\n\n"+
					"CipherTrust Client Error: "+err.Error(),
			)
			return
		}
		client.CCKMConfig.AwsOperationTimeout = aws_operation_timeout
		client.CCKMConfig.OCIOperationTimeout = oci_operation_timeout
		client.ReplicationDelay = replication_delay_ms
		client.Log = providerLogger
		resp.DataSourceData = client
		resp.ResourceData = client
		if !client.IsCDSPaaS {
			client.Log.Info(fmt.Sprintf("CipherTrust Manager version %s", client.CMFullVersion))
		} else {
			client.Log.Info("CipherTrust Data Security Platform as a Service (CDSPaas)")
		}
	} else {
		client, err := common.NewCMClientBoot(ctx, id, &address, tlsOpts, rest_api_timeout)
		if err != nil {
			resp.Diagnostics.AddError(
				"Unable to Create CipherTrust API Client",
				"An unexpected error occurred when creating the CipherTrust API client. "+
					"If the error is not clear, please contact the provider developers.\n\n"+
					"CipherTrust Client Error: "+err.Error(),
			)
			return
		}
		client.CCKMConfig.AwsOperationTimeout = aws_operation_timeout
		client.CCKMConfig.OCIOperationTimeout = oci_operation_timeout
		client.ReplicationDelay = replication_delay_ms
		client.Log = providerLogger
		resp.DataSourceData = client
		resp.ResourceData = client
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
		cte.NewDataSourceCTESignatureSets,
		cte.NewDataSourceCTEPolicy,
		cte.NewDataSourceLDTGroupCommSvc,
		cte.NewDataSourceCTELDTGroupCommSvcClients,
		cte.NewDataSourceCTEClientGroup,
		cte.NewDataSourceCTEClientGroupClients,
		cte.NewDataSourceCTEClientGuardPoint,
		cte.NewDataSourceCTEClientGroupGuardPoint,
		cte.NewDataSourceCTEClientGroupDesignatedPrimarySet,
		cte.NewDataSourceCTECSIGroup,
		cm.NewDataSourceRegTokens,
		cte.NewDataSourceCTEClients,
		cm.NewDataSourceCertificateAuthorities,
		connections.NewDataSourceScpConnection,
		cm.NewDataSourcePrometheus,
		connections.NewDataSourceGCPConnection,
		connections.NewDataSourceAzureConnection,
		azure.NewDataSourceAzureVaultsList,
		cm.NewDataSourceScheduler,
		connections.NewDataSourceAWSConnection,
		aws.NewDataSourceAWSAccountDetails,
		aws.NewDataSourceAWSKeys,
		aws.NewDataSourceAWSCustomKeyStore,
		aws.NewDataSourceAWSXKSKeys,
		aws.NewDataSourceAWSKms,
		aws.NewDataSourceAWSIAMUsers,
		aws.NewDataSourceAWSIAMRoles,
		aws.NewDataSourceAWSCloudHSMKeys,
		connections.NewDataSourceOCIConnection,
		oci.NewDataSourceGetOCIRegions,
		oci.NewDataSourceGetOCICompartments,
		oci.NewDataSourceGetOCIVaults,
		oci.NewDataSourceGetOCIBuckets,
		oci.NewDataSourceOCIVault,
		oci.NewDataSourceOCIKeys,
		oci.NewDataSourceOCIVersions,
		oci.NewDataSourceOCICompartmentsList,
		aws.NewDataSourceAWSKeyRotationList,
	}
}

// Resources defines the resources implemented in the provider.
func (p *ciphertrustProvider) Resources(ctx context.Context) []func() resource.Resource {
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
		cte.NewResourceCTEPolicyKeyRule,
		cte.NewResourceCTEPolicyLDTKeyRule,
		cte.NewResourceCTEPolicySecurityRule,
		cte.NewResourceCTEPolicySignatureRule,
		cte.NewResourceCTEClientGroupGP,
		cte.NewResourceCTEProfile,
		cte.NewResourceCTEClientGroupDesignatedPrimarySet,
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
		cm.NewResourceCMClusterNode,
		cm.NewResourceCMInterface,
		cm.NewResourceInterfaceCertificateRenewal,
		cm.NewResourceCMLicense,
		cm.NewResourceCMNTP,
		cm.NewResourceCMTrialLicense,
		cm.NewResourceCMPrometheus,
		connections.NewResourceGCPConnection,
		connections.NewResourceAzureConnection,
		azure.NewResourceAzureVault,
		cm.NewResourceScheduler,
		cm.NewResourceCMDomain,
		cm.NewResourceCMLogForwarders,
		cm.NewResourceCMPasswordPolicy,
		cm.NewResourceCMPolicy,
		cm.NewResourceCMPolicyAttachment,
		cm.NewResourceCMProperty,
		cm.NewResourceCMProxy,
		cm.NewResourceCMSyslog,
		aws.NewResourceCCKMAWSKMS,
		aws.NewResourceAWSKey,
		aws.NewResourceAWSByokKey,
		aws.NewResourceAWSKeyMaterial,
		aws.NewResourceAWSKeyRotation,
		aws.NewResourceAWSPolicyTemplate,
		aws.NewResourceAWSCustomKeyStore,
		aws.NewResourceAWSXKSKey,
		aws.NewResourceAWSCloudHSMKey,
		connections.NewResourceCCKMOCIConnection,
		oci.NewResourceCCKMOCIVault,
		oci.NewResourceCCKMOCIAcl,
		oci.NewResourceCCKMOCIByokKey,
		oci.NewResourceCCKMOCIByokVersion,
		oci.NewResourceCCKMOCIVersion,
		oci.NewResourceCCKMOCIKey,
		aws.NewResourceCCKMAWSAcl,
	}
}
