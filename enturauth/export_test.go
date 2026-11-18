package enturauth

// Wrap is the authentication middleware Access installs, for the external tests.
var Wrap = (*Authenticator).wrap
