package networkenrich

func unknown() Attribution { return Attribution{Status: "unknown"} }

// Classify reports evidence of an edge or cloud service from aliases and
// scanner fingerprints alone. It is ClassifyNetwork without addresses.
func Classify(cnames, fingerprints []string) (Attribution, Attribution) {
	return ClassifyNetwork(cnames, nil, fingerprints)
}
