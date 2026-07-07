package cm

const notFoundError = "status: 404"

// notMemberOfGroupErrorFragment is a substring of the body CipherTrust returns
// when DELETE /usermgmt/groups/{name}/users/{user_id} is called for a user
// that isn't actually a member of the group. We use Contains rather than a
// status check so we don't swallow other unrelated 400 responses.
const notMemberOfGroupErrorFragment = "not a member"
