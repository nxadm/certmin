package main

type actionFunc func() (string, error)

func skimCerts(locations []string, remoteAll, remoteInters bool) (string, error) {
	return "", nil
}

func verifyChain(locations, rootFiles, interFiles []string, remoteChain, remoteInters bool) (string, error) {
	return "", nil
}

func verifyKey(location, keyFile string, passwordBytes []byte, prompt bool) (string, error) {
	return "", nil
}
