package environments

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/redhat-developer/kam/pkg/pipelines/argocd"
	"github.com/redhat-developer/kam/pkg/pipelines/config"
	"github.com/redhat-developer/kam/pkg/pipelines/meta"
	"github.com/redhat-developer/kam/pkg/pipelines/namespaces"
	res "github.com/redhat-developer/kam/pkg/pipelines/resources"
	"github.com/redhat-developer/kam/pkg/pipelines/roles"
	"github.com/spf13/afero"
	v1 "k8s.io/api/rbac/v1"
)

// AppLinks represents whether or not apps are linked to environments.
type AppLinks int

const (
	// AppsToEnvironments indicates that apps should be linked to Environments.
	AppsToEnvironments AppLinks = iota
	// EnvironmentsToApps indicates that environments should be linked to Apps.
	EnvironmentsToApps
)

const (
	kustomization  = "kustomization.yaml"
	vcsSourceLabel = "app.openshift.io/vcs-source"
)

type envBuilder struct {
	files           res.Resources
	pipelinesConfig *config.PipelinesConfig
	fs              afero.Fs
	saName          string
	appLinks        AppLinks
	gitOpsRepoURL   string
	repoPath        string
}

// Build generates a set of resources from the manifest, related to the
// environment and apps and services.
func Build(fs afero.Fs, m *config.Manifest, saName string, o AppLinks) (res.Resources, error) {
	files := res.Resources{}
	cfg := m.GetPipelinesConfig()

	parsed, err := url.Parse(m.GitOpsURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse GitOpsURL %q: %w", m.GitOpsURL, err)
	}
	repoPath := strings.TrimPrefix(strings.TrimSuffix(parsed.Path, ".git"), "/")

	eb := &envBuilder{
		fs:              fs,
		files:           files,
		pipelinesConfig: cfg,
		saName:          saName,
		appLinks:        o,
		gitOpsRepoURL:   m.GitOpsURL,
		repoPath:        repoPath,
	}
	return eb.files, m.Walk(eb)
}

func (b *envBuilder) Application(env *config.Environment, app *config.Application) error {
	appPath := filepath.ToSlash(filepath.Join(config.PathForApplication(env, app)))
	appFiles, err := filesForApplication(env, b.repoPath, appPath, app)
	if err != nil {
		return err
	}
	b.files = res.Merge(appFiles, b.files)
	return nil
}

func (b *envBuilder) Service(app *config.Application, env *config.Environment, svc *config.Service) error {
	svcPath := config.PathForService(app, env, svc.Name)
	svcFiles, err := filesForService(svcPath)
	if err != nil {
		return err
	}
	b.files = res.Merge(svcFiles, b.files)
	// RoleBinding is created only when an environment has a service and the
	// CICD environment is defined.
	if b.pipelinesConfig == nil {
		return nil
	}
	envBasePath := filepath.ToSlash(filepath.Join(config.PathForEnvironment(env), "env", "base"))
	envBindingPath := filepath.ToSlash(filepath.Join(envBasePath, fmt.Sprintf("%s-rolebinding.yaml", env.Name)))
	if _, ok := b.files[envBindingPath]; !ok {
		b.files[envBindingPath] = createRoleBinding(env, b.pipelinesConfig.Name, b.saName)
	}
	return nil
}

func (b *envBuilder) Environment(env *config.Environment) error {
	envPath := filepath.ToSlash(filepath.Join(config.PathForEnvironment(env), "env"))
	basePath := filepath.ToSlash(filepath.Join(envPath, "base"))
	envFiles := filesForEnvironment(basePath, env, b.gitOpsRepoURL)
	kustomizedFilenames, err := ListFiles(b.fs, basePath)
	if err != nil {
		return fmt.Errorf("failed to list initial files for %s: %s", basePath, err)
	}
	envBindingPath := filepath.ToSlash(filepath.Join(basePath, fmt.Sprintf("%s-rolebinding.yaml", env.Name)))
	if _, ok := b.files[envBindingPath]; ok {
		envFiles[envBindingPath] = b.files[envBindingPath]
	}

	argocdAdminPath := filepath.ToSlash(filepath.Join(basePath, "argocd-admin.yaml"))
	if _, ok := b.files[argocdAdminPath]; !ok {
		envFiles[argocdAdminPath] = argocd.MakeApplicationControllerAdmin(env.Name)
	}

	for k := range envFiles {
		kustomizedFilenames[filepath.Base(k)] = true
	}

	kustomizationPath := filepath.ToSlash(filepath.Join(basePath, kustomization))
	relApps, err := appsFromEnvironment(env, kustomizationPath, b.appLinks)
	if err != nil {
		return err
	}
	envFiles[kustomizationPath] = &res.Kustomization{
		Bases:     relApps,
		Resources: kustomizedFilenames.Items(),
	}
	overlaysPath := filepath.ToSlash(filepath.Join(envPath, "overlays"))
	relPath, err := filepath.Rel(overlaysPath, basePath)
	if err != nil {
		return err
	}
	envFiles[filepath.ToSlash(filepath.Join(overlaysPath, kustomization))] = &res.Kustomization{Bases: []string{filepath.ToSlash(relPath)}}
	b.files = res.Merge(envFiles, b.files)
	return nil
}

func filesForEnvironment(basePath string, env *config.Environment, gitOpsRepoURL string) res.Resources {
	envFiles := res.Resources{}
	filename := filepath.ToSlash(filepath.Join(basePath, fmt.Sprintf("%s-environment.yaml", env.Name)))
	envFiles[filename] = namespaces.Create(env.Name, gitOpsRepoURL)
	return envFiles
}

func filesForApplication(env *config.Environment, fullname, appPath string, app *config.Application) (res.Resources, error) {
	envFiles := res.Resources{}
	basePath := filepath.ToSlash(filepath.Join(appPath, "base"))
	overlaysPath := filepath.ToSlash(filepath.Join(appPath, "overlays"))
	overlaysFile := filepath.ToSlash(filepath.Join(overlaysPath, kustomization))
	overlayRel, err := filepath.Rel(overlaysPath, basePath)
	if err != nil {
		return nil, err
	}
	baseKustomization := filepath.ToSlash(filepath.Join(appPath, "base", kustomization))
	relServices := []string{}
	for _, v := range app.Services {
		svcPath := config.PathForService(app, env, v.Name)
		relService, err := filepath.Rel(filepath.Dir(baseKustomization), svcPath)
		if err != nil {
			return nil, err
		}
		relServices = append(relServices, filepath.ToSlash(relService))
	}

	envFiles[filepath.ToSlash(filepath.Join(appPath, kustomization))] = &res.Kustomization{
		Bases: []string{"overlays"},
		CommonLabels: map[string]string{
			vcsSourceLabel: fullname,
		},
	}
	envFiles[filepath.ToSlash(filepath.Join(appPath, "base", kustomization))] = &res.Kustomization{
		Bases: relServices,
	}
	envFiles[overlaysFile] = &res.Kustomization{
		Bases: []string{filepath.ToSlash(overlayRel)},
	}
	return envFiles, nil
}

func createRoleBinding(env *config.Environment, cicdNS, saName string) *v1.RoleBinding {
	sa := roles.CreateServiceAccount(meta.NamespacedName(cicdNS, saName))
	return roles.CreateRoleBinding(meta.NamespacedName(env.Name, fmt.Sprintf("%s-rolebinding", env.Name)), sa, "ClusterRole", "edit")
}

func filesForService(svcPath string) (res.Resources, error) {
	envFiles := res.Resources{}
	basePath := filepath.ToSlash(filepath.Join(svcPath, "base"))
	overlaysPath := filepath.ToSlash(filepath.Join(svcPath, "overlays"))
	overlaysFile := filepath.ToSlash(filepath.Join(overlaysPath, kustomization))
	overlayRel, err := filepath.Rel(overlaysPath, basePath)
	if err != nil {
		return nil, err
	}
	envFiles[filepath.ToSlash(filepath.Join(svcPath, kustomization))] = &res.Kustomization{Bases: []string{"overlays"}}
	envFiles[filepath.ToSlash(filepath.Join(svcPath, "base", kustomization))] = &res.Kustomization{Bases: []string{"./config"}}
	envFiles[overlaysFile] = &res.Kustomization{Bases: []string{filepath.ToSlash(overlayRel)}}

	return envFiles, nil
}

// StringSet is a set of strings.
type StringSet map[string]bool

// Items returns a slice of the elements in the set.
func (s StringSet) Items() []string {
	names := []string{}
	for k := range s {
		names = append(names, k)
	}
	sort.Strings(names)
	return names
}

// ListFiles returns a set of filenames.
func ListFiles(fs afero.Fs, base string) (StringSet, error) {
	files := map[string]bool{}
	err := afero.Walk(fs, base, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			if os.IsNotExist(err) {
				return nil
			}
			return err
		}
		if info.IsDir() {
			return nil
		}
		filename := strings.TrimPrefix(filepath.ToSlash(path), filepath.ToSlash(base)+"/")
		if filename == kustomization {
			return nil
		}
		files[filename] = true
		return nil
	})
	return files, err
}

func appsFromEnvironment(env *config.Environment, kustomizationPath string, appLinks AppLinks) ([]string, error) {
	relApps := []string{}
	if appLinks != EnvironmentsToApps {
		return nil, nil
	}
	for _, v := range env.Apps {
		appPath := config.PathForApplication(env, v)
		relApp, err := filepath.Rel(filepath.Dir(kustomizationPath), appPath)
		if err != nil {
			return nil, err
		}
		relApps = append(relApps, filepath.Join(relApp, "overlays"))
	}
	return relApps, nil
}
