package argocd

import (
	"path/filepath"
	"sort"

	// This is a hack because ArgoCD doesn't support a compatible (code-wise)
	// version of k8s in common with kam.

	argov1 "github.com/redhat-developer/kam/pkg/pipelines/argocd/operator/v1alpha1"
	argoappv1 "github.com/redhat-developer/kam/pkg/pipelines/argocd/v1alpha1"
	"sigs.k8s.io/yaml"

	"github.com/redhat-developer/kam/pkg/pipelines/config"
	"github.com/redhat-developer/kam/pkg/pipelines/meta"
	res "github.com/redhat-developer/kam/pkg/pipelines/resources"
)

const (
	vcsSourceLabel = "app.openshift.io/vcs-source"
	appLabel       = "app.kubernetes.io/name"
)

var (
	applicationTypeMeta = meta.TypeMeta(
		"Application",
		"argoproj.io/v1alpha1",
	)

	syncPolicy = &argoappv1.SyncPolicy{
		Automated: &argoappv1.SyncPolicyAutomated{
			Prune:    true,
			SelfHeal: true,
		},
	}

	ignoreDifferencesFields = []argoappv1.ResourceIgnoreDifferences{
		{Group: "argoproj.io", Kind: "Application", JSONPointers: []string{"/status"}},
		{Group: "triggers.tekton.dev", Kind: "EventListener", JSONPointers: []string{"/status"}},
		{Group: "triggers.tekton.dev", Kind: "TriggerTemplate", JSONPointers: []string{"/status"}},
		{Group: "triggers.tekton.dev", Kind: "TriggerBinding", JSONPointers: []string{"/status"}},
		{Group: "route.openshift.io", Kind: "Route", JSONPointers: []string{"/spec/host"}},
		{Group: "bitnami.com", Kind: "SealedSecret", JSONPointers: []string{"/status"}},
	}

	resourceExclusions = excludeResources{
		[]resource{
			{
				APIGroups: []string{"tekton.dev"},
				Kinds:     []string{"TaskRun", "PipelineRun"},
				Clusters:  []string{"*"},
			},
		},
	}
)

type excludeResources struct {
	Resources []resource
}

type resource struct {
	APIGroups []string `json:"apiGroups"`
	Kinds     []string `json:"kinds"`
	Clusters  []string `json:"clusters"`
}

const (
	// ArgoCDNamespace is the default namespace for ArgoCD installations.
	ArgoCDNamespace = "argocd"

	defaultServer      = "https://kubernetes.default.svc"
	defaultProject     = "default"
	argoCDResourceFile = "argocd.yaml"
)

// Build creates and returns a set of resources to be used for the ArgoCD
// configuration.
func Build(argoNS, repoURL string, m *config.Manifest) (res.Resources, error) {
	if repoURL == "" {
		return res.Resources{}, nil
	}

	argoCDConfig := m.GetArgoCDConfig()
	if argoCDConfig == nil {
		return res.Resources{}, nil
	}

	files := make(res.Resources)
	eb := &argocdBuilder{repoURL: repoURL, files: files, argoCDConfig: argoCDConfig, argoNS: argoNS}
	err := m.Walk(eb)
	if err != nil {
		return nil, err
	}
	err = argoCDConfigResources(m.Config, m.GitOpsURL, eb.files)
	if err != nil {
		return nil, err
	}
	return eb.files, err
}

type argocdBuilder struct {
	repoURL      string
	argoCDConfig *config.ArgoCDConfig
	files        res.Resources
	argoNS       string
}

func (b *argocdBuilder) Application(env *config.Environment, app *config.Application) error {
	basePath := filepath.Join(config.PathForArgoCD())
	argoFiles := res.Resources{}
	filename := filepath.Join(basePath, env.Name+"-"+app.Name+"-app.yaml")

	argoFiles[filename] = makeApplication(app, env.Name+"-"+app.Name, b.argoNS,
		defaultProject,
		env.Name,
		clusterForEnv(env),
		makeAppSource(env, app, b.repoURL))
	b.files = res.Merge(argoFiles, b.files)
	return nil
}

func (b *argocdBuilder) Environment(env *config.Environment) error {
	basePath := filepath.Join(config.PathForArgoCD())
	argoFiles := res.Resources{}
	filename := filepath.Join(basePath, env.Name+"-env-app.yaml")

	argoFiles[filename] = makeApplication(
		nil,
		env.Name+"-env", b.argoNS,
		defaultProject,
		env.Name,
		clusterForEnv(env),
		makeEnvSource(env, b.repoURL))
	b.files = res.Merge(argoFiles, b.files)
	return nil
}

func argoCDConfigResources(cfg *config.Config, repoURL string, files res.Resources) error {
	if cfg.ArgoCD.Namespace == "" {
		return nil
	}
	basePath := filepath.Join(config.PathForArgoCD())
	filename := filepath.Join(basePath, "kustomization.yaml")
	files[filepath.Join(basePath, "argo-app.yaml")] =
		ignoreDifferences(makeApplication(nil, "argo-app", cfg.ArgoCD.Namespace,
			defaultProject, cfg.ArgoCD.Namespace, defaultServer,
			&argoappv1.ApplicationSource{RepoURL: repoURL, Path: basePath}))
	if cfg.Pipelines != nil {
		files[filepath.Join(basePath, "cicd-app.yaml")] = ignoreDifferences(
			makeApplication(nil, "cicd-app", cfg.ArgoCD.Namespace, defaultProject, cfg.Pipelines.Name, defaultServer,
				&argoappv1.ApplicationSource{RepoURL: repoURL, Path: filepath.Join(config.PathForPipelines(cfg.Pipelines), "overlays")}))
	}
	argoResource, err := argoCDResource(cfg.ArgoCD.Namespace)
	if err != nil {
		return err
	}
	files[filepath.Join(basePath, argoCDResourceFile)] = argoResource
	resourceNames := []string{}
	for k := range files {
		resourceNames = append(resourceNames, filepath.Base(k))
	}
	sort.Strings(resourceNames)
	files[filename] = &res.Kustomization{Resources: resourceNames}
	return nil
}

func makeAppSource(env *config.Environment, app *config.Application, repoURL string) *argoappv1.ApplicationSource {
	if app.ConfigRepo == nil {
		return &argoappv1.ApplicationSource{
			RepoURL: repoURL,
			Path:    filepath.Join(config.PathForApplication(env, app), "overlays"),
		}
	}
	return &argoappv1.ApplicationSource{
		RepoURL:        app.ConfigRepo.URL,
		Path:           app.ConfigRepo.Path,
		TargetRevision: app.ConfigRepo.TargetRevision,
	}
}

func makeEnvSource(env *config.Environment, repoURL string) *argoappv1.ApplicationSource {
	envPath := filepath.Join(config.PathForEnvironment(env), "env")
	envBasePath := filepath.Join(envPath, "overlays")
	return &argoappv1.ApplicationSource{
		RepoURL: repoURL,
		Path:    envBasePath,
	}
}

func ignoreDifferences(app *argoappv1.Application) *argoappv1.Application {
	app.Spec.IgnoreDifferences = ignoreDifferencesFields
	return app
}

func argoCDResource(ns string) (*argov1.ArgoCD, error) {
	b, err := yaml.Marshal(resourceExclusions.Resources)
	if err != nil {
		return nil, err
	}
	return &argov1.ArgoCD{
		TypeMeta:   meta.TypeMeta("ArgoCD", "argoproj.io/v1alpha1"),
		ObjectMeta: meta.ObjectMeta(meta.NamespacedName(ns, "argocd")),
		Spec: argov1.ArgoCDSpec{
			ResourceExclusions: string(b),
			Server: argov1.ArgoCDServerSpec{
				Route: argov1.ArgoCDRouteSpec{Enabled: true},
			},
		},
	}, nil
}

func makeApplication(app *config.Application, appName, argoNS, project, ns, server string, source *argoappv1.ApplicationSource) *argoappv1.Application {
	options := []meta.ObjectMetaOpt{}
	if app != nil {
		options = append(options, meta.AddLabels(map[string]string{
			appLabel: app.Name,
		}))
	}
	return &argoappv1.Application{
		TypeMeta: applicationTypeMeta,
		ObjectMeta: meta.ObjectMeta(meta.NamespacedName(argoNS, appName),
			options...,
		),
		Spec: argoappv1.ApplicationSpec{
			Project: project,
			Destination: argoappv1.ApplicationDestination{
				Namespace: ns,
				Server:    server,
			},
			Source:     *source,
			SyncPolicy: syncPolicy,
		},
	}
}

func clusterForEnv(env *config.Environment) string {
	if env.Cluster != "" {
		return env.Cluster
	}
	return defaultServer
}
