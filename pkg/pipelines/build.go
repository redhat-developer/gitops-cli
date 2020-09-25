package pipelines

import (
	"github.com/redhat-developer/kam/pkg/pipelines/argocd"
	"github.com/redhat-developer/kam/pkg/pipelines/config"
	"github.com/redhat-developer/kam/pkg/pipelines/environments"
	res "github.com/redhat-developer/kam/pkg/pipelines/resources"
	"github.com/redhat-developer/kam/pkg/pipelines/yaml"
	"github.com/spf13/afero"
)

// BuildParameters is a struct that provides flags for the BuildResources
// command.
type BuildParameters struct {
	PipelinesFolderPath string
	OutputPath          string
}

// BuildResources builds all resources from a pipelines.
func BuildResources(o *BuildParameters, appFs afero.Fs) error {
	m, err := config.LoadManifest(appFs, o.PipelinesFolderPath)
	if err != nil {
		return err
	}
	resources, err := buildResources(appFs, m)
	if err != nil {
		return err
	}
	_, err = yaml.WriteResources(appFs, o.OutputPath, resources)
	return err
}

func buildResources(fs afero.Fs, m *config.Manifest) (res.Resources, error) {
	resources := res.Resources{}

	argoCD := m.GetArgoCDConfig()
	appLinks := environments.EnvironmentsToApps
	if argoCD != nil {
		appLinks = environments.AppsToEnvironments
	}

	envs, err := environments.Build(fs, m, saName, appLinks)
	if err != nil {
		return nil, err
	}
	resources = res.Merge(envs, resources)

	elFiles, err := buildEventListenerResources(m.GitOpsURL, m)
	if err != nil {
		return nil, err
	}

	resources = res.Merge(elFiles, resources)
	argoApps, err := argocd.Build(argocd.ArgoCDNamespace, m.GitOpsURL, m)
	if err != nil {
		return nil, err
	}
	resources = res.Merge(argoApps, resources)
	return resources, nil
}
