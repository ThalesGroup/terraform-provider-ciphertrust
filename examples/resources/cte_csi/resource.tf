resource "ciphertrust_cte_csigroup" "cte_csi" {
		name="csi_group"
		description = "test123"
                k8s_namespace= "K8sNamespace_1"
                k8s_storage_class =  "K8sStorageClass_1"
}