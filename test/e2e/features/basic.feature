Feature: Basic test
    Checks whether KAM top-level commands behave correctly.

    Scenario: KAM version
        When executing "kam version" succeeds
        Then stderr should be empty
        And stdout should contain "kam version"

    Scenario: KAM bootstrap
        # Given create gitops temporary directory
        # Then go to the gitops temporary directory
        # And executing "gh repo create $GITOPS_REPO_URL --public --confirm"
        # Then stderr should be empty
        When executing "kam bootstrap --service-repo-url $SERVICE_REPO_URL --gitops-repo-url $GITOPS_REPO_URL --image-repo $GITOPS_REPO_URL --dockercfgjson $DOCKERCONFIGJSON_PATH --git-host-access-token $GITHUB_TOKEN --output bootstrapresources --push-to-git=true" succeeds
        Then stderr should be empty
