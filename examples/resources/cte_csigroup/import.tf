/*
Terraform import functionality :- This is used to import real life infrastructure under terraform management by mapping it to state file.

1) Uncomment the import block and provide the correct resource id. You can add multiple import blocks as well just make sure they have a unique label.

2) terraform plan -generate-config-out=generated.tf 
-- This will generate a generated.tf file which will have the imported resource block.

3) terraform apply
-- This will import the resource and map it to your state file.

4) terraform plan
-- To verify it should show no changes.
Note:- (label) is very important here, make sure the resources you import and the ones you create in main.tf have different labels.
So they don't try to update each other.

Now the resource created through terraform are managed through main.tf as always and imported resources can be managed through generated.tf.
*/

/*
import {
    to = ciphertrust_cte_csigroup.label1
    id = "id_of_the_resource"
}

*/




