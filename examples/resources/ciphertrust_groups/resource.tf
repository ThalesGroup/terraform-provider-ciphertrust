resource "ciphertrust_groups" "group1" {
    name = "group1"
    user_ids = [
        ciphertrust_user.user_admin1.id,
    ]
}