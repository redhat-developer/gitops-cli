package resources

// Kustomization is a structural representation of the Kustomize file format.
type Kustomization struct {
	Resources    []string          `json:"resources,omitempty"`
	Bases        []string          `json:"bases,omitempty"`
	CommonLabels map[string]string `json:"commonLabels,omitempty"`
}
