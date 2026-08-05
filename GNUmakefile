
default: fmt  install


build:
	go build -v ./...

install: build
	go install -v ./...

lint:
	golangci-lint run

generate:
	cd tools; go generate ./...

fmt:
	gofmt -s -w -e .

test:
	go test -v -count=1 -cover -timeout=120s -parallel=10 ./...

testacc:
	rm -rf /work/ctp.log
	rm -rf /work/tf.log
	rm -rf /work/terraform-provider-ciphertrust-v1/*.log
	rm -rf internal/provider/ctp.log

#	TF_ACC=1 go test -v -count=1 -timeout 120m ./...


# START OF SMOKE

#	TF_ACC=1 go test -v -count=1 -timeout 120m ./internal/provider/ -run TestCckmAWSByokKeyMultiRegion
#	TF_ACC=1 go test -v -count=1 -timeout 120m ./internal/provider/ -run TestCckmAWSByokKeyMultiRegionReplication
#	TF_ACC=1 go test -v -count=1 -timeout 120m ./internal/provider/ -run TestCckmAWS
#	TF_ACC=1 go test -v -count=1 -timeout 120m ./internal/provider/ -run TestCckmAWSAcl
#	TF_ACC=1 go test -v -count=1 -timeout 120m ./internal/provider/ -run TestCckmAWSByokKeyAES
#	TF_ACC=1 go test -v -count=1 -timeout 120m ./internal/provider/ -run TestCckmAWSByokKeyCreateRejections
#	TF_ACC=1 go test -v -count=1 -timeout 120m ./internal/provider/ -run TestCckmAWSByokKeyMultiRegionAndMakePrimary
#	TF_ACC=1 go test -v -count=1 -timeout 120m ./internal/provider/ -run TestCckmAWSByokKeyMultiRegionAndPrimaryRegion
#	TF_ACC=1 go test -v -count=1 -timeout 120m ./internal/provider/ -run TestCckmAWSByokKeyPendingDeletionRefresh
#	TF_ACC=1 go test -v -count=1 -timeout 120m ./internal/provider/ -run TestCckmAWSByokKeyPendingDeletionUpdate
#	TF_ACC=1 go test -v -count=1 -timeout 120m ./internal/provider/ -run TestCckmAWSByokKeyPolicyUpdates
#	TF_ACC=1 go test -v -count=1 -timeout 120m ./internal/provider/ -run TestCckmAWSByokKeyRSA
#	TF_ACC=1 go test -v -count=1 -timeout 120m ./internal/provider/ -run TestCckmAWSCustomKeyStore
#	TF_ACC=1 go test -v -count=1 -timeout 120m ./internal/provider/ -run TestCckmAWSCustomKeyStoreCreateUpdate
#	TF_ACC=1 go test -v -count=1 -timeout 120m ./internal/provider/ -run TestCckmAWSCustomKeyStoreEmptyAwsParams
#	TF_ACC=1 go test -v -count=1 -timeout 120m ./internal/provider/ -run TestCckmAWSCustomKeyStoreEmptyLocalHostedParams
#	TF_ACC=1 go test -v -count=1 -timeout 120m ./internal/provider/ -run TestCckmAWSDataSourceAccountDetails
#	TF_ACC=1 go test -v -count=1 -timeout 120m ./internal/provider/ -run TestCckmAWSDataSourceCustomKeyStore
#	TF_ACC=1 go test -v -count=1 -timeout 120m ./internal/provider/ -run TestCckmAWSDataSourceKey
#	TF_ACC=1 go test -v -count=1 -timeout 120m ./internal/provider/ -run TestCckmAWSDataSourceKms
#	TF_ACC=1 go test -v -count=1 -timeout 120m ./internal/provider/ -run TestCckmAWSDataSourceXksKey
#	TF_ACC=1 go test -v -count=1 -timeout 120m ./internal/provider/ -run TestCckmAWSKeyKmsDeleteRecovery

#	TF_ACC=1 go test -v -count=1 -timeout 120m ./internal/provider/ -run TestCckmAWSKeyMaterial
#	TF_ACC=1 go test -v -count=1 -timeout 120m ./internal/provider/ -run TestCckmAWSKeyMaterialCDSPaaSNotSupported
#	TF_ACC=1 go test -v -count=1 -timeout 120m ./internal/provider/ -run TestCckmAWSKeyMaterialCreate$
#	TF_ACC=1 go test -v -count=1 -timeout 120m ./internal/provider/ -run TestCckmAWSKeyMaterialCreateAndUpdate
#	TF_ACC=1 go test -v -count=1 -timeout 120m ./internal/provider/ -run TestCckmAWSKeyMaterialCombinedUpdates
#	TF_ACC=1 go test -v -count=1 -timeout 120m ./internal/provider/ -run TestCckmAWSKeyMaterialRepairPendingImport
#	TF_ACC=1 go test -v -count=1 -timeout 120m ./internal/provider/ -run TestCckmAWSKeyMaterialRepairPendingRotation
#	TF_ACC=1 go test -v -count=1 -timeout 120m ./internal/provider/ -run TestCckmAWSKeyMaterialRepairCombined
#	TF_ACC=1 go test -v -count=1 -timeout 120m ./internal/provider/ -run TestCckmAWSKeyMaterialMROOBDeleteMaterial
#	TF_ACC=1 go test -v -count=1 -timeout 120m ./internal/provider/ -run TestCckmAWSKeyMaterialRepairMultiRegionPendingImportAndRotation
#	TF_ACC=1 go test -v -count=1 -timeout 120m ./internal/provider/ -run TestCckmAWSKeyMaterialAdoptPendingRotation
#	TF_ACC=1 go test -v -count=1 -timeout 120m ./internal/provider/ -run TestCckmAWSKeyMaterialAdoptPendingMRRotation
#	TF_ACC=1 go test -v -count=1 -timeout 120m ./internal/provider/ -run TestCckmAWSKeyMaterialMRPendingImportFirstMaterial

#	TF_ACC=1 go test -v -count=1 -timeout 120m ./internal/provider/ -run TestCckmAWSKeyMaterialPlanValidation
#	TF_ACC=1 go test -v -count=1 -timeout 120m ./internal/provider/ -run TestCckmAWSKeyMultiRegionNative
#	TF_ACC=1 go test -v -count=1 -timeout 120m ./internal/provider/ -run TestCckmAWSKeyMultiRegionNativeAndMakePrimary
#	TF_ACC=1 go test -v -count=1 -timeout 120m ./internal/provider/ -run TestCckmAWSKeyMultiRegionNativeAndPrimaryRegion
#	TF_ACC=1 go test -v -count=1 -timeout 120m ./internal/provider/ -run TestCckmAWSKeyNative$
#	TF_ACC=1 go test -v -count=1 -timeout 120m ./internal/provider/ -run TestCckmAWSKeyNativeCreateRejections
#	TF_ACC=1 go test -v -count=1 -timeout 120m ./internal/provider/ -run TestCckmAWSKeyNativeImport
#	TF_ACC=1 go test -v -count=1 -timeout 120m ./internal/provider/ -run TestCckmAWSKeyNativePendingDeletionRefresh
#	TF_ACC=1 go test -v -count=1 -timeout 120m ./internal/provider/ -run TestCckmAWSKeyNativePendingDeletionUpdate
#	TF_ACC=1 go test -v -count=1 -timeout 120m ./internal/provider/ -run TestCckmAWSKeyPolicyUpdates
#	TF_ACC=1 go test -v -count=1 -timeout 120m ./internal/provider/ -run TestCckmAWSKeyRotationNative
#	TF_ACC=1 go test -v -count=1 -timeout 120m ./internal/provider/ -run TestCckmAWSKms
#	TF_ACC=1 go test -v -count=1 -timeout 120m ./internal/provider/ -run TestCckmAWSNativeKeyMinimalConfig
#	TF_ACC=1 go test -v -count=1 -timeout 120m ./internal/provider/ -run TestCckmAWSPolicyTemplate
#	TF_ACC=1 go test -v -count=1 -timeout 120m ./internal/provider/ -run TestCckmAWSXks
#	TF_ACC=1 go test -v -count=1 -timeout 120m ./internal/provider/ -run TestCckmAWSXksUnlinkedKey$
#	TF_ACC=1 go test -v -count=1 -timeout 120m ./internal/provider/ -run TestCckmAWSXksUnlinkedKeyCreateModifyPlan
#	TF_ACC=1 go test -v -count=1 -timeout 120m ./internal/provider/ -run TestCckmAWSXksLinkedKeyCreateModifyPlan
#	TF_ACC=1 go test -v -count=1 -timeout 120m ./internal/provider/ -run TestCckmOCI
#	TF_ACC=1 go test -v -count=1 -timeout 120m ./internal/provider/ -run TestCckmOCIAcl
#	TF_ACC=1 go test -v -count=1 -timeout 120m ./internal/provider/ -run TestCckmOCIByokKey$
#	TF_ACC=1 go test -v -count=1 -timeout 120m ./internal/provider/ -run TestCckmOCIByokKeyRestoreFromBackup
#	TF_ACC=1 go test -v -count=1 -timeout 120m ./internal/provider/ -run TestCckmOCIByokInvalidCreateConfigs
#	TF_ACC=1 go test -v -count=1 -timeout 120m ./internal/provider/ -run TestCckmOCIKeyNative$
#	TF_ACC=1 go test -v -count=1 -timeout 120m ./internal/provider/ -run TestCckmOCIKeyInvalidCreateConfigs

#	TF_ACC=1 go test -v -count=1 -timeout 120m ./internal/provider/ -run TestCckmOCIDataSourceConnection
#	TF_ACC=1 go test -v -count=1 -timeout 120m ./internal/provider/ -run TestCckmOCIDatasourceVault

#	TF_ACC=1 go test -v -count=1 -timeout 120m ./internal/provider/ -run TestCckmOCIVault
#	TF_ACC=1 go test -v -count=1 -timeout 120m ./internal/provider/ -run TestCckmSchedulersInvalidAttribs


me:
	go build -o ./terraform-provider-ciphertrust
	cp terraform-provider-ciphertrust ~/.terraform.d/plugins/thales.com/terraform/ciphertrust/1.0.1/linux_amd64/


.PHONY: fmt lint test testacc build install generate


