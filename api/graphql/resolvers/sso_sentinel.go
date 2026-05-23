package resolvers

import "errors"

// errAccountManagementDelegated is the canonical error every internal account-
// management mutation returns when PHOTOVIEW_HEADER_AUTH_ENABLED=1. Sharing one
// sentinel makes the UI's "SSO mode" branch easy to recognize and lets us add
// new reject paths without re-deciding wording.
//
// Lives in its own file because gqlgen overwrites user.go on regeneration; any
// package-level declaration we add to user.go gets discarded as "unknown code".
var errAccountManagementDelegated = errors.New("account management is delegated to the SSO provider")
