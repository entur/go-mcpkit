package enturauth

// Wrap is the authentication middleware Access installs, for the external tests.
var Wrap = (*Authenticator).wrap

// PauseAfterKeyLookup makes a's verifications call pause between the key
// lookup and the admission decision; nil removes it. Set it only while no
// verification runs.
func PauseAfterKeyLookup(a *Authenticator, pause func()) { a.afterKeyLookup = pause }
