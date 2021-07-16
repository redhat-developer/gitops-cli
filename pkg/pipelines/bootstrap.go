package pipelines

import (
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/mitchellh/go-homedir"
	"github.com/openshift/odo/pkg/log"
	"github.com/spf13/afero"
	corev1 "k8s.io/api/core/v1"
	v1rbac "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	"github.com/redhat-developer/kam/pkg/pipelines/argocd"
	"github.com/redhat-developer/kam/pkg/pipelines/config"
	"github.com/redhat-developer/kam/pkg/pipelines/deployment"
	"github.com/redhat-developer/kam/pkg/pipelines/dryrun"
	"github.com/redhat-developer/kam/pkg/pipelines/eventlisteners"
	"github.com/redhat-developer/kam/pkg/pipelines/imagerepo"
	"github.com/redhat-developer/kam/pkg/pipelines/ioutils"
	"github.com/redhat-developer/kam/pkg/pipelines/meta"
	"github.com/redhat-developer/kam/pkg/pipelines/namespaces"
	"github.com/redhat-developer/kam/pkg/pipelines/pipelines"
	res "github.com/redhat-developer/kam/pkg/pipelines/resources"
	"github.com/redhat-developer/kam/pkg/pipelines/roles"
	"github.com/redhat-developer/kam/pkg/pipelines/routes"
	"github.com/redhat-developer/kam/pkg/pipelines/scm"
	"github.com/redhat-developer/kam/pkg/pipelines/secrets"
	"github.com/redhat-developer/kam/pkg/pipelines/tasks"
	"github.com/redhat-developer/kam/pkg/pipelines/triggers"
	"github.com/redhat-developer/kam/pkg/pipelines/yaml"
	pipelinev1 "github.com/tektoncd/pipeline/pkg/apis/pipeline/v1beta1"
)

const (
	// Kustomize constants for kustomization.yaml
	Kustomize = "kustomization.yaml"

	namespacesPath        = "01-namespaces/cicd-environment.yaml"
	rolesPath             = "02-rolebindings/pipeline-service-role.yaml"
	rolebindingsPath      = "02-rolebindings/pipeline-service-rolebinding.yaml"
	serviceAccountPath    = "02-rolebindings/pipeline-service-account.yaml"
	argocdAdminRolePath   = "02-rolebindings/argocd-admin.yaml"
	gitopsTasksPath       = "03-tasks/deploy-from-source-task.yaml"
	commitStatusTaskPath  = "03-tasks/set-commit-status-task.yaml"
	ciPipelinesPath       = "04-pipelines/ci-dryrun-from-push-pipeline.yaml"
	appCiPipelinesPath    = "04-pipelines/app-ci-pipeline.yaml"
	pushTemplatePath      = "06-templates/ci-dryrun-from-push-template.yaml"
	appCIPushTemplatePath = "06-templates/app-ci-build-from-push-template.yaml"
	eventListenerPath     = "07-eventlisteners/cicd-event-listener.yaml"
	routePath             = "08-routes/gitops-webhook-event-listener.yaml"

	dockerSecretName = "regcred"

	authTokenSecretName = "git-host-access-token"
	basicAuthTokenName  = "git-host-basic-auth-token"

	saName              = "pipeline"
	roleBindingName     = "pipelines-service-role-binding"
	webhookSecretLength = 20

	pipelinesFile     = "pipelines.yaml"
	bootstrapImage    = "nginxinc/nginx-unprivileged:latest"
	appCITemplateName = "app-ci-template"
	version           = 1
)

// BootstrapOptions is a struct that provides the optional flags
type BootstrapOptions struct {
	GitOpsRepoURL            string // This is where the pipelines and configuration are.
	GitOpsWebhookSecret      string // This is the secret for authenticating hooks from your GitOps repo.
	Prefix                   string
	DockerConfigJSONFilename string
	ImageRepo                string // This is where built images are pushed to.
	OutputPath               string // Where to write the bootstrapped files to?
	GitHostAccessToken       string // The auth token to use to access repositories.
	Overwrite                bool   // This allows to overwrite if there is an existing gitops repository
	ServiceRepoURL           string // This is the full URL to your GitHub repository for your app source.
	SaveTokenKeyRing         bool   // If true, the access-token will be saved in the keyring
	ServiceWebhookSecret     string // This is the secret for authenticating hooks from your app source.
	PrivateRepoDriver        string // Records the type of the GitOpsRepoURL driver if not a well-known host.
	PushToGit                bool   // If true, gitops repository is pushed to remote git repository.
}

// PolicyRules to be bound to service account
var (
	Rules = []v1rbac.PolicyRule{
		{
			APIGroups: []string{""},
			Resources: []string{"namespaces", "services"},
			Verbs:     []string{"patch", "get", "create"},
		},
		{
			APIGroups: []string{"rbac.authorization.k8s.io"},
			Resources: []string{"clusterroles", "roles"},
			Verbs:     []string{"bind", "patch", "get"},
		},
		{
			APIGroups: []string{"rbac.authorization.k8s.io"},
			Resources: []string{"clusterrolebindings", "rolebindings"},
			Verbs:     []string{"get", "create", "patch"},
		},
		{
			APIGroups: []string{"apps"},
			Resources: []string{"deployments"},
			Verbs:     []string{"get", "create", "patch"},
		},
		{
			APIGroups: []string{"argoproj.io"},
			Resources: []string{"applications", "argocds"},
			Verbs:     []string{"get", "create", "patch"},
		},
	}
)

// Bootstrap is the entry-point from the CLI for bootstrapping the GitOps
// configuration.
func Bootstrap(o *BootstrapOptions, appFs afero.Fs) error {
	err := checkPipelinesFileExists(appFs, o.OutputPath, o.Overwrite, o.PushToGit)
	if err != nil {
		return err
	}
	err = maybeMakeHookSecrets(o)
	if err != nil {
		return err
	}

	bootstrapped, otherResources, err := bootstrapResources(o, appFs)
	if err != nil {
		return fmt.Errorf("failed to bootstrap resources: %v", err)
	}

	m := bootstrapped[pipelinesFile].(*config.Manifest)
	built, err := buildResources(appFs, m)
	if err != nil {
		return fmt.Errorf("failed to build resources: %v", err)
	}

	bootstrapped = res.Merge(built, bootstrapped)
	log.Successf("Created dev, stage and CICD environments")
	_, err = yaml.WriteResources(appFs, o.OutputPath, bootstrapped)
	if err != nil {
		return fmt.Errorf("failed to write resources: %w", err)
	}
	_, err = yaml.WriteResources(appFs, filepath.Join(o.OutputPath, ".."), otherResources)
	if err != nil {
		return fmt.Errorf("failed to write resources: %w", err)
	}

	return nil
}

func maybeMakeHookSecrets(o *BootstrapOptions) error {
	if o.GitOpsWebhookSecret == "" {
		gitopsSecret, err := secrets.GenerateString(webhookSecretLength)
		if err != nil {
			return fmt.Errorf("failed to generate GitOps webhook secret: %v", err)
		}
		o.GitOpsWebhookSecret = gitopsSecret
	}
	if o.ServiceWebhookSecret == "" {
		appSecret, err := secrets.GenerateString(webhookSecretLength)
		if err != nil {
			return fmt.Errorf("failed to generate application webhook secret: %v", err)
		}
		o.ServiceWebhookSecret = appSecret
	}
	return nil
}

func bootstrapResources(o *BootstrapOptions, appFs afero.Fs) (res.Resources, res.Resources, error) {
	ns := namespaces.NamesWithPrefix(o.Prefix)
	appRepo, err := scm.NewRepository(o.ServiceRepoURL)
	if err != nil {
		return nil, nil, err
	}
	repoName, err := repoFromURL(appRepo.URL())
	if err != nil {
		return nil, nil, fmt.Errorf("invalid app repo URL: %v", err)
	}
	// No image repo was supplied so create the default OS internal image registry
	if o.ImageRepo == "" {
		o.ImageRepo = ns["cicd"] + "/" + repoName
	}
	isInternalRegistry, imageRepo, err := imagerepo.ValidateImageRepo(o.ImageRepo)
	if err != nil {
		return nil, nil, err
	}

	log.Success("Options used:")
	log.Progressf("  Service repository: %s", o.ServiceRepoURL)
	log.Progressf("  GitOps repository: %s", o.GitOpsRepoURL)
	log.Progressf("  Image repository: %s", imageRepo)
	if !isInternalRegistry {
		log.Progressf("  Path to config.json: %s", o.DockerConfigJSONFilename)
	}
	log.Progressf("  Output folder: %s", o.OutputPath)
	log.Progressf("  Overwrite output folder: %s", strconv.FormatBool(o.Overwrite))
	log.Progressf("")

	gitOpsRepo, err := scm.NewRepository(o.GitOpsRepoURL)
	if err != nil {
		return nil, nil, err
	}
	bootstrapped, otherResources, err := createInitialFiles(
		appFs, gitOpsRepo, o)
	if err != nil {
		return nil, nil, err
	}
	appName := repoToAppName(repoName)
	serviceName := repoName
	secretName := secrets.MakeServiceWebhookSecretName(ns["dev"], serviceName)
	envs, configEnv, err := bootstrapEnvironments(appRepo, o.Prefix, secretName, ns)
	if err != nil {
		return nil, nil, err
	}
	if o.PrivateRepoDriver != "" {
		host, err := scm.HostnameFromURL(o.GitOpsRepoURL)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to get hostname from URL %q: %w", o.GitOpsRepoURL, err)
		}
		configEnv.Git = &config.GitConfig{Drivers: map[string]string{host: o.PrivateRepoDriver}}
	}
	m := createManifest(gitOpsRepo.URL(), configEnv, envs...)

	devEnv := m.GetEnvironment(ns["dev"])
	if devEnv == nil {
		return nil, nil, errors.New("unable to bootstrap without dev environment")
	}

	app := m.GetApplication(ns["dev"], appName)
	if app == nil {
		return nil, nil, errors.New("unable to bootstrap without application")
	}
	svcFiles, err := bootstrapServiceDeployment(devEnv, app)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create bootstrap service: %w", err)
	}
	var opaqueSecret *corev1.Secret
	opaqueSecret, err = secrets.CreateUnsealedSecret(meta.NamespacedName(ns["cicd"], secretName),
		o.ServiceWebhookSecret,
		eventlisteners.WebhookSecretKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create secret")
	}

	cfg := m.GetPipelinesConfig()
	if cfg == nil {
		return nil, nil, errors.New("failed to find a pipeline configuration - unable to continue bootstrap")
	}
	secretFilename := filepath.ToSlash(filepath.Join("secrets", secretName+".yaml"))
	otherResources[secretFilename] = opaqueSecret
	bindingName, imageRepoBindingFilename, svcImageBinding := createSvcImageBinding(cfg, devEnv, appName, serviceName, imageRepo, !isInternalRegistry)
	bootstrapped = res.Merge(svcImageBinding, bootstrapped)

	kustomizePath := filepath.Join(config.PathForPipelines(cfg), "base", "kustomization.yaml")
	k, ok := bootstrapped[kustomizePath].(res.Kustomization)
	if !ok {
		return nil, nil, fmt.Errorf("no kustomization for the %s environment found", kustomizePath)
	}
	if isInternalRegistry {
		filenames, resources, err := imagerepo.CreateInternalRegistryResources(
			cfg, roles.CreateServiceAccount(meta.NamespacedName(cfg.Name, saName)),
			imageRepo, o.GitOpsRepoURL)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to get resources for internal image repository: %v", err)
		}
		bootstrapped = res.Merge(resources, bootstrapped)
		k.AddResources(filenames...)
	}

	// This is specific to bootstrap, because there's only one service.
	devEnv.Apps[0].Services[0].Pipelines = &config.Pipelines{
		Integration: &config.TemplateBinding{
			Bindings: append([]string{bindingName}, devEnv.Pipelines.Integration.Bindings...),
		},
	}
	bootstrapped[pipelinesFile] = m

	k.AddResources(imageRepoBindingFilename)
	bootstrapped[kustomizePath] = k

	bootstrapped = res.Merge(svcFiles, bootstrapped)
	return bootstrapped, otherResources, nil
}

func bootstrapServiceDeployment(dev *config.Environment, app *config.Application) (res.Resources, error) {
	svc := dev.Apps[0].Services[0]
	svcBase := filepath.Join(config.PathForService(app, dev, svc.Name), "base", "config")
	resources := res.Resources{}
	// TODO: This should change if we add Namespace to Environment.
	// We'd need to create the resources in the namespace _of_ the Environment.
	resources[filepath.Join(svcBase, "100-deployment.yaml")] = deployment.Create(app.Name, dev.Name, svc.Name, bootstrapImage, deployment.ContainerPort(8080))
	containerSvc := createBootstrapService(app.Name, dev.Name, svc.Name)
	resources[filepath.Join(svcBase, "200-service.yaml")] = containerSvc
	r, err := routes.NewFromService(containerSvc)
	if err != nil {
		return nil, err
	}
	resources[filepath.Join(svcBase, "300-route.yaml")] = r
	resources[filepath.Join(svcBase, "kustomization.yaml")] = &res.Kustomization{
		Resources: []string{
			"100-deployment.yaml",
			"200-service.yaml",
			"300-route.yaml",
		}}
	return resources, nil
}

func bootstrapEnvironments(repo scm.Repository, prefix, secretName string, ns map[string]string) ([]*config.Environment, *config.Config, error) {
	envs := []*config.Environment{}
	var pipelinesConfig *config.PipelinesConfig
	for _, k := range []string{"cicd", "dev", "stage"} {
		v := ns[k]
		if k == "cicd" {
			pipelinesConfig = &config.PipelinesConfig{Name: prefix + "cicd"}
		} else {
			env := &config.Environment{Name: v}
			if k == "dev" {
				svc, err := serviceFromRepo(repo.URL(), secretName, ns["cicd"])
				if err != nil {
					return nil, nil, err
				}
				app, err := applicationFromRepo(repo.URL(), svc)
				if err != nil {
					return nil, nil, err
				}
				app.Services = []*config.Service{svc}
				env.Apps = []*config.Application{app}
				env.Pipelines = defaultPipelines(repo)
			}
			envs = append(envs, env)
		}
	}
	cfg := &config.Config{Pipelines: pipelinesConfig, ArgoCD: &config.ArgoCDConfig{Namespace: argocd.ArgoCDNamespace}}
	return envs, cfg, nil
}

func serviceFromRepo(repoURL, secretName, secretNS string) (*config.Service, error) {
	repo, err := repoFromURL(repoURL)
	if err != nil {
		return nil, err
	}
	return &config.Service{
		Name:      repo,
		SourceURL: repoURL,
		Webhook: &config.Webhook{
			Secret: &config.Secret{
				Name:      secretName,
				Namespace: secretNS,
			},
		},
	}, nil
}

func applicationFromRepo(repoURL string, service *config.Service) (*config.Application, error) {
	repo, err := repoFromURL(repoURL)
	if err != nil {
		return nil, err
	}
	return &config.Application{
		Name:     repoToAppName(repo),
		Services: []*config.Service{service},
	}, nil
}

func repoFromURL(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	parts := strings.Split(u.Path, "/")
	return strings.TrimSuffix(parts[len(parts)-1], ".git"), nil
}

func orgRepoFromURL(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	parts := strings.Split(u.Path, "/")
	orgRepo := strings.Join(parts[len(parts)-2:], "/")
	return strings.TrimSuffix(orgRepo, ".git"), nil
}

func createBootstrapService(appName, ns, name string) *corev1.Service {
	svc := &corev1.Service{
		TypeMeta:   meta.TypeMeta("Service", "v1"),
		ObjectMeta: meta.ObjectMeta(meta.NamespacedName(ns, name)),
		Spec: corev1.ServiceSpec{
			Ports: []corev1.ServicePort{
				{
					Name:       "http",
					Protocol:   corev1.ProtocolTCP,
					Port:       8080,
					TargetPort: intstr.FromInt(8080)},
			},
		},
	}
	labels := map[string]string{
		deployment.KubernetesAppNameLabel: name,
		deployment.KubernetesPartOfLabel:  appName,
	}
	svc.ObjectMeta.Labels = labels
	svc.Spec.Selector = labels
	return svc
}

func repoToAppName(repoName string) string {
	return "app-" + repoName
}

func defaultPipelines(r scm.Repository) *config.Pipelines {
	return &config.Pipelines{
		Integration: &config.TemplateBinding{
			Template: appCITemplateName,
			Bindings: []string{r.PushBindingName()},
		},
	}
}

// Checks whether the pipelines.yaml is present in the output path specified.
func checkPipelinesFileExists(appFs afero.Fs, outputPath string, overWrite bool, pushToGit bool) error {

	if overWrite {
		return nil
	}
	checkList := []string{pipelinesFile}
	if pushToGit {
		checkList = append(checkList, ".git")
	}

	if err := errorIfFileExists(appFs, outputPath, checkList...); err != nil {
		return err
	}

	secretsFolderExists, _ := ioutils.IsExisting(appFs, filepath.Join(outputPath, "..", "secrets"))
	if secretsFolderExists {
		return fmt.Errorf("the secrets folder located as a sibling of the output folder %s already exists. Rerun with --overwrite", outputPath)
	}

	return nil
}

func errorIfFileExists(appFs afero.Fs, outputPath string, files ...string) error {
	for _, file := range files {
		exists, _ := ioutils.IsExisting(appFs, filepath.Join(outputPath, file))
		if exists {
			return fmt.Errorf("%s in output path already exists. If you want to replace your existing files, please rerun with --overwrite", file)
		}
	}
	return nil
}

func createInitialFiles(fs afero.Fs, repo scm.Repository, o *BootstrapOptions) (res.Resources, res.Resources, error) {
	cicd := &config.PipelinesConfig{Name: o.Prefix + "cicd"}
	pipelineConfig := &config.Config{Pipelines: cicd}
	manifest := createManifest(repo.URL(), pipelineConfig)
	initialFiles := res.Resources{
		pipelinesFile: manifest,
	}
	resources, otherResources, err := createCICDResources(fs, repo, cicd, o)
	if err != nil {
		return nil, nil, err
	}

	files := getResourceFiles(resources)
	prefixedResources := addPrefixToResources(pipelinesPath(manifest.Config), resources)
	initialFiles = res.Merge(prefixedResources, initialFiles)

	pipelinesConfigKustomizations := addPrefixToResources(
		config.PathForPipelines(manifest.Config.Pipelines),
		getCICDKustomization(files))
	initialFiles = res.Merge(pipelinesConfigKustomizations, initialFiles)

	return initialFiles, otherResources, nil
}

// createDockerSecret creates a secret that allows pushing images to upstream repositories.
func createDockerSecret(fs afero.Fs, dockerConfigJSONFilename, secretNS string) (*corev1.Secret, error) {
	if dockerConfigJSONFilename == "" {
		return nil, errors.New("failed to generate path to file: --dockerconfigjson flag is not provided")
	}
	authJSONPath, err := homedir.Expand(dockerConfigJSONFilename)
	if err != nil {
		return nil, fmt.Errorf("failed to generate path to file: %v", err)
	}
	f, err := fs.Open(authJSONPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read Docker config %#v : %s", authJSONPath, err)
	}
	defer f.Close()

	dockerSecret, err := secrets.CreateUnsealedDockerConfigSecret(meta.NamespacedName(secretNS, dockerSecretName), f)
	if err != nil {
		return nil, err
	}
	return dockerSecret, nil
}

// createCICDResources creates resources for OpenShift pipelines.
func createCICDResources(fs afero.Fs, repo scm.Repository, pipelineConfig *config.PipelinesConfig, o *BootstrapOptions) (res.Resources, res.Resources, error) {
	cicdNamespace := pipelineConfig.Name
	// key: path of the resource
	// value: YAML content of the resource
	outputs := map[string]interface{}{}
	otherOutputs := map[string]interface{}{}
	githubSecret, err := secrets.CreateUnsealedSecret(meta.NamespacedName(cicdNamespace, eventlisteners.GitOpsWebhookSecret), o.GitOpsWebhookSecret, eventlisteners.WebhookSecretKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate GitHub Webhook Secret: %w", err)
	}
	unEncSecretPath := filepath.Join("secrets", "gitops-webhook-secret.yaml")
	otherOutputs[unEncSecretPath] = githubSecret
	outputs[namespacesPath] = namespaces.Create(cicdNamespace, o.GitOpsRepoURL)
	outputs[rolesPath] = roles.CreateClusterRole(meta.NamespacedName("", roles.ClusterRoleName), Rules)

	sa := roles.CreateServiceAccount(meta.NamespacedName(cicdNamespace, saName))

	if o.DockerConfigJSONFilename != "" {
		dockerUnencryptedSecret, err := createDockerSecret(fs, o.DockerConfigJSONFilename, cicdNamespace)
		if err != nil {
			return nil, nil, err
		}
		if dockerUnencryptedSecret != nil {
			otherOutputs[filepath.Join("secrets", "docker-config.yaml")] = dockerUnencryptedSecret
			log.Success("Authentication tokens for docker config not sealed in secrets")
		}
		outputs[serviceAccountPath] = roles.AddSecretToSA(sa, dockerSecretName)
	}

	if o.GitHostAccessToken != "" {
		err := generateSecrets(outputs, otherOutputs, sa, cicdNamespace, o)
		if err != nil {
			return nil, nil, err
		}
	}

	outputs[argocdAdminRolePath] = argocd.MakeApplicationControllerAdmin(cicdNamespace)

	outputs[rolebindingsPath] = roles.CreateClusterRoleBinding(meta.NamespacedName("", roleBindingName), sa, "ClusterRole", roles.ClusterRoleName)
	script, err := dryrun.MakeScript("kubectl", cicdNamespace)
	if err != nil {
		return nil, otherOutputs, err
	}
	outputs[gitopsTasksPath] = tasks.CreateDeployFromSourceTask(cicdNamespace, script)
	// currently, the commit status task doesn't support enterprise repository
	// enable it by default once the status task supports enterprise repository
	if o.PrivateRepoDriver == "" {
		outputs[commitStatusTaskPath] = tasks.CreateCommitStatusTask(cicdNamespace)
	}
	outputs[ciPipelinesPath] = removeCommitStatus(pipelines.CreateCIPipeline(meta.NamespacedName(cicdNamespace, "ci-dryrun-from-push-pipeline"), cicdNamespace), o.PrivateRepoDriver)
	outputs[appCiPipelinesPath] = removeCommitStatus(pipelines.CreateAppCIPipeline(meta.NamespacedName(cicdNamespace, "app-ci-pipeline")), o.PrivateRepoDriver)
	pushBinding, pushBindingName := repo.CreatePushBinding(cicdNamespace)
	outputs[filepath.ToSlash(filepath.Join("05-bindings", pushBindingName+".yaml"))] = pushBinding
	outputs[pushTemplatePath] = triggers.CreateCIDryRunTemplate(cicdNamespace, saName)
	outputs[appCIPushTemplatePath] = triggers.CreateDevCIBuildPRTemplate(cicdNamespace, saName)
	outputs[eventListenerPath] = eventlisteners.Generate(repo, cicdNamespace, saName, eventlisteners.GitOpsWebhookSecret)
	log.Success("OpenShift Pipelines resources created")
	route, err := eventlisteners.GenerateRoute(cicdNamespace)
	if err != nil {
		return nil, nil, err
	}
	outputs[routePath] = route
	log.Success("Openshift Route for EventListener created")
	return outputs, otherOutputs, nil
}

func createManifest(gitOpsRepoURL string, configEnv *config.Config, envs ...*config.Environment) *config.Manifest {
	return &config.Manifest{
		GitOpsURL:    gitOpsRepoURL,
		Environments: envs,
		Config:       configEnv,
		Version:      version,
	}
}

func getCICDKustomization(files []string) res.Resources {
	return res.Resources{
		"overlays/kustomization.yaml": res.Kustomization{
			Bases: []string{"../base"},
		},
		"base/kustomization.yaml": res.Kustomization{
			Resources: files,
		},
	}
}

func pipelinesPath(m *config.Config) string {
	return filepath.Join(config.PathForPipelines(m.Pipelines), "base")
}

func addPrefixToResources(prefix string, files res.Resources) map[string]interface{} {
	updated := map[string]interface{}{}
	for k, v := range files {
		updated[filepath.Join(prefix, k)] = v
	}
	return updated
}

func getResourceFiles(r res.Resources) []string {
	files := []string{}
	for k := range r {
		files = append(files, k)
	}
	sort.Strings(files)
	return files
}

func generateSecrets(outputs res.Resources, otherOutputs res.Resources, sa *corev1.ServiceAccount, ns string, o *BootstrapOptions) error {
	tokenSecret, err := secrets.CreateUnsealedSecret(meta.NamespacedName(
		ns, authTokenSecretName), o.GitHostAccessToken, "token")
	if err != nil {
		return fmt.Errorf("failed to generate Secret: %w", err)
	}
	otherOutputs[filepath.Join("secrets", "git-host-access-token.yaml")] = tokenSecret
	outputs[serviceAccountPath] = roles.AddSecretToSA(sa, tokenSecret.Name)

	// basic auth token is used by Tekton pipelines to access private repositories
	secretTargetHost, err := repoURL(o.ServiceRepoURL)
	if err != nil {
		return fmt.Errorf("failed to parse the Service Repo URL %q: %w", o.ServiceRepoURL, err)
	}
	basicAuthSecret := secrets.CreateUnsealedBasicAuthSecret(meta.NamespacedName(
		ns, basicAuthTokenName), o.GitHostAccessToken, meta.AddAnnotations(map[string]string{
		"tekton.dev/git-0": secretTargetHost,
	}))
	otherOutputs[filepath.Join("secrets", basicAuthTokenName+".yaml")] = basicAuthSecret
	outputs[serviceAccountPath] = roles.AddSecretToSA(sa, basicAuthSecret.Name)
	return nil
}

// remove the commit status task and it's dependency
func removeCommitStatus(pipeline *pipelinev1.Pipeline, driver string) *pipelinev1.Pipeline {
	if driver == "" {
		return pipeline
	}
	setPendingStatusTask := "set-pending-status"
	pipeline.Spec.Finally = nil
	tasks := []pipelinev1.PipelineTask{}
	for _, task := range pipeline.Spec.Tasks {
		if len(task.RunAfter) > 0 && task.RunAfter[0] == setPendingStatusTask {
			task.RunAfter = nil
		}
		if task.Name != setPendingStatusTask {
			tasks = append(tasks, task)
		}
	}
	pipeline.Spec.Tasks = tasks
	return pipeline
}
