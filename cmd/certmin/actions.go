package main

// actionFunc is a type for actions and their expected output as string and error.
type actionFunc func() (string, error)

// skimCerts prints relevant information of local or remote certificates,
// optionally including a remote chain.
func skimCerts(locations []string, remotes, issuerURIs, noRemoteRoots, keep bool) (string, error) {
	return "", nil
}

// verifyChain verifies that local or remote certificates match their chain,
// supplied as local files, system-trust and/or remotely.
func verifyChain(locations, rootFiles, interFiles []string,
	remotes, issuerURIs, noRemoteRoots, keep bool) (string, error) {
	return "", nil
}

// verifyKey verifies a local or renote certificate and a key match
func verifyKey(location, keyFile string, passwordBytes []byte, prompt, keep bool) (string, error) {
	return "", nil
}
