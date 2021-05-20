package kamsuite

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"log"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/cucumber/godog"
	"github.com/cucumber/messages-go/v10"
	"github.com/jenkins-x/go-scm/scm"
	"github.com/jenkins-x/go-scm/scm/factory"
	"github.com/redhat-developer/kam/pkg/pipelines/git"
)

const (
	podStatus = "oc get pods -n openshift-gitops -l app.kubernetes.io/name=openshift-gitops-server -o jsonpath='{.items[*].status.phase}'"
)

// FeatureContext defines godog.Suite steps for the test suite.
func FeatureContext(s *godog.Suite) {

	// KAM related steps
	s.Step(`^directory "([^"]*)" should exist$`,
		DirectoryShouldExist)

	s.Step(`^gitops repository is created$`,
		createRepository)

	s.Step(`^login argocd API server$`,
		loginArgoAPIServerLogin)

	s.Step(`^application "([^"]*)" should be in "([^"]*)" state$`,
		applicationState)

	s.Step(`^Wait for "(\d*)" seconds$`,
		waitForTime)

	s.BeforeSuite(func() {
		fmt.Println("Before suite")
		if !envVariableCheck() {
			os.Exit(1)
		}
	})

	s.AfterSuite(func() {
		fmt.Println("After suite")
	})

	s.BeforeFeature(func(this *messages.GherkinDocument) {
		fmt.Println("Before feature")
	})

	s.AfterFeature(func(this *messages.GherkinDocument) {
		fmt.Println("After feature")
	})

	s.BeforeScenario(func(this *messages.Pickle) {
		fmt.Println("Before scenario")
	})

	s.AfterScenario(func(*messages.Pickle, error) {
		fmt.Println("After scenario")
		// re := regexp.MustCompile(`[a-z]+`)
		// scm := re.FindAllString(os.Getenv("GITOPS_REPO_URL"), 2)[1]

		// switch scm {
		// case "github":
		// 	deleteGithubRepository(os.Getenv("GITOPS_REPO_URL"), os.Getenv("GIT_ACCESS_TOKEN"))
		// case "gitlab":
		// 	deleteGitlabRepoStep := []string{"repo", "delete", strings.Split(strings.Split(os.Getenv("GITOPS_REPO_URL"), ".com/")[1], ".")[0], "-y"}
		// 	ok, errMessage := deleteGitlabRepository(deleteGitlabRepoStep)
		// 	if !ok {
		// 		fmt.Println(errMessage)
		// 	}
		// default:
		// 	fmt.Println("SCM is not supported")
		// }
	})
}

func envVariableCheck() bool {
	envVars := []string{"SERVICE_REPO_URL", "GITOPS_REPO_URL", "IMAGE_REPO", "DOCKERCONFIGJSON_PATH", "GIT_ACCESS_TOKEN"}
	val, ok := os.LookupEnv("CI")
	if !ok {
		for _, envVar := range envVars {
			_, ok := os.LookupEnv(envVar)
			if !ok {
				fmt.Printf("%s is not set\n", envVar)
				return false
			}
		}

		re := regexp.MustCompile(`[a-z]+`)
		scm := re.FindAllString(os.Getenv("GITOPS_REPO_URL"), 2)[1]

		switch scm {
		case "github":
			os.Setenv("GITHUB_TOKEN", os.Getenv("GIT_ACCESS_TOKEN"))
		case "gitlab":
			os.Setenv("GITLAB_TOKEN", os.Getenv("GIT_ACCESS_TOKEN"))
		default:
			fmt.Println("SCM is not supported")
		}
	} else {
		if val == "prow" {
			fmt.Printf("Running e2e test in OpenShift CI\n")
			os.Setenv("SERVICE_REPO_URL", "https://github.com/kam-bot/taxi")
			os.Setenv("GITOPS_REPO_URL", "https://github.com/kam-bot/taxi-"+os.Getenv("PRNO"))
			os.Setenv("IMAGE_REPO", "quay.io/kam-bot/taxi")
			os.Setenv("DOCKERCONFIGJSON_PATH", os.Getenv("KAM_QUAY_DOCKER_CONF_SECRET_FILE"))
			os.Setenv("GIT_ACCESS_TOKEN", os.Getenv("GITHUB_TOKEN"))
		} else {
			fmt.Printf("You cannot run e2e test locally against OpenShift CI\n")
			return false
		}
		return true
	}
	return true
}

func deleteGitlabRepository(arg []string) (bool, string) {
	var stderr bytes.Buffer
	cmd := exec.Command("glab", arg...)
	fmt.Println("gitlab command is : ", cmd.Args)
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		return false, stderr.String()
	}
	return true, stderr.String()
}

func deleteGithubRepository(repoURL, token string) {
	repo, err := git.NewRepository(repoURL, token)
	if err != nil {
		log.Fatal(err)
	}
	parsed, err := url.Parse(repoURL)
	if err != nil {
		log.Fatalf("failed to parse repository URL %q: %v", repoURL, err)
	}
	repoName, err := git.GetRepoName(parsed)
	if err != nil {
		log.Fatal(err)
	}
	_, err = repo.Repositories.Delete(context.TODO(), repoName)
	if err != nil {
		log.Printf("unable to delete repository: %v", err)
	} else {
		log.Printf("Successfully deleted repository: %q", repoURL)
	}
}

func createRepository() error {
	repoName := strings.Split(os.Getenv("GITOPS_REPO_URL"), "/")[4]
	parsed, err := url.Parse(os.Getenv("GITOPS_REPO_URL"))
	if err != nil {
		return err
	}

	parsed.User = url.UserPassword("", os.Getenv("GITHUB_TOKEN"))
	client, err := factory.FromRepoURL(parsed.String())
	if err != nil {
		return err
	}

	ri := &scm.RepositoryInput{
		Private:     false,
		Description: "repocreate",
		Namespace:   "",
		Name:        repoName,
	}
	_, _, err = client.Repositories.Create(context.Background(), ri)
	if err != nil {
		return err
	}

	return nil
}

func waitForTime(wait int) error {
	time.Sleep(time.Duration(wait) * time.Second)
	return nil
}

func applicationState(appName string, appState string) error {
	err := argoAppStatusMatch(appState, appName)
	if err != nil {
		return fmt.Errorf("Error is : %v", err)
	}
	return nil
}

func loginArgoAPIServerLogin() error {
	var stderr bytes.Buffer
	argocdPath, err := executableBinaryPath("argocd")
	if err != nil {
		return err
	}

	argocdServer, err := argocdAPIServer()
	if err != nil {
		return err
	}

	argocdPassword, err := argocdAPIServerPassword()
	if err != nil {
		return err
	}

	cmd := exec.Command(argocdPath, "login", "--username", "admin", "--password", argocdPassword, argocdServer, "--grpc-web", "--insecure")
	cmd.Stderr = &stderr
	err = cmd.Run()
	if err != nil {
		fmt.Println(stderr.String())
		return err
	}
	return nil
}

func executableBinaryPath(executable string) (string, error) {
	path, err := exec.LookPath(executable)
	if err != nil {
		return "", err
	}
	return path, nil
}

func argocdAPIServer() (string, error) {
	var stdout bytes.Buffer

	ocPath, err := executableBinaryPath("oc")
	if err != nil {
		return "", err
	}

	deployments := []string{"openshift-gitops-server", "openshift-gitops-repo-server",
		"openshift-gitops-redis", "openshift-gitops-applicationset-controller", "kam", "cluster"}

	for deployment := range deployments {
		if waitForDeploymentsUpAndRunning("openshift-gitops", deployments[deployment]); err != nil {
			return "", err
		}
	}

	cmd := exec.Command(ocPath, "get", "routes", "-n", "openshift-gitops",
		"-o", "jsonpath='{.items[?(@.metadata.name==\"openshift-gitops-server\")].spec.host}'")
	cmd.Stdout = &stdout
	err = cmd.Run()
	if err != nil {
		return "", err
	}
	return strings.Trim(stdout.String(), "'"), nil
}

func argocdAPIServerPassword() (string, error) {
	var stdout, stderr bytes.Buffer
	ocPath, err := executableBinaryPath("oc")
	if err != nil {
		return "", err
	}

	cmd := exec.Command(ocPath, "get", "secret", "openshift-gitops-cluster", "-n", "openshift-gitops", "-o", "jsonpath='{.data.admin\\.password}'")

	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err = cmd.Run()
	if err != nil {
		return "", err
	}

	data, err := base64.StdEncoding.DecodeString(strings.Trim(stdout.String(), "'"))
	if err != nil {
		return "", err
	}

	return string(data), nil
}

func waitForDeploymentsUpAndRunning(namespace string, deploymentName string) error {
	var stderr, stdout bytes.Buffer
	ocPath, err := executableBinaryPath("oc")
	if err != nil {
		return err
	}
	cmd := exec.Command(ocPath, "rollout", "status", "deployment", deploymentName, "-n", namespace)

	cmd.Stderr = &stderr
	cmd.Stdout = &stdout
	err = cmd.Run()
	if err == nil && strings.Contains(stdout.String(), "successfully rolled out") {
		return nil
	}
	return fmt.Errorf("Error is : %v", stderr.String())
}

func argoAppStatusMatch(matchString string, appName string) error {
	var stdout, stderr bytes.Buffer
	argocdPath, err := executableBinaryPath("argocd")
	if err != nil {
		return err
	}

	appList := []string{"app", "list"}
	cmd := exec.Command(argocdPath, appList...)
	cmd.Stdout = &stdout
	if err = cmd.Run(); err != nil {
		return err
	}
	fmt.Println(stdout.String())

	apps := []string{"argo-app", "dev-app-taxi", "dev-env"}

	for app := range apps {
		appList := []string{"app", "get", apps[app]}
		cmd := exec.Command(argocdPath, appList...)
		cmd.Stdout = &stdout
		if err = cmd.Run(); err != nil {
			return err
		}
		fmt.Println(stdout.String())
	}

	re, _ := regexp.Compile(appName + ".+")
	appDetailsString := re.FindString(stdout.String())
	if strings.Contains(appDetailsString, matchString) {
		return nil
	}
	return fmt.Errorf("Error is : %v", stderr.String())
}
