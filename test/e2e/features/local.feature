@local
Feature: Local test
    This feature file captures local test automation.
    Due to certain technical challenges in OpenShiftCI test infra
    we are keeping test scenario in local feature file for verifying the bits locally.
    Once the CI challenges are fixed, we move these test under basic tag.

    Scenario: Execute KAM bootstrap command with default and --push-to-git=true flags
        When executing "kam bootstrap --service-repo-url $SERVICE_REPO_URL --gitops-repo-url $GITOPS_REPO_URL --git-host-access-token $GIT_ACCESS_TOKEN --push-to-git=true" succeeds
        Then stderr should be empty

    Scenario: Execute KAM bootstrap command with default flags
        When executing "kam bootstrap --service-repo-url $SERVICE_REPO_URL --gitops-repo-url $GITOPS_REPO_URL --git-host-access-token $GIT_ACCESS_TOKEN --overwrite" succeeds
        Then stderr should be empty
        And deleting directory "gitops" succeeds
        Then stderr should be empty
    
    Scenario: Execute KAM bootstrap command with --output and --push-to-git=true flags
        When executing "kam bootstrap --service-repo-url $SERVICE_REPO_URL --gitops-repo-url $GITOPS_REPO_URL --git-host-access-token $GIT_ACCESS_TOKEN --push-to-git=true --output bootstrapresources" succeeds
        Then stderr should be empty
    
    Scenario: Execute KAM bootstrap command with default flags
        When executing "kam bootstrap --service-repo-url $SERVICE_REPO_URL --gitops-repo-url $GITOPS_REPO_URL --git-host-access-token $GIT_ACCESS_TOKEN --overwrite" succeeds
        Then stderr should be empty
        And executing "cd gitops"
        And executing "git init ." succeeds
        And executing "git add ." succeeds
        And executing "git commit -m 'Initial commit.'" succeeds
        And executing "git remote add origin $GITOPS_REPO_URL" succeeds
        And executing "git push -u origin main" succeeds
        Then stderr should be empty