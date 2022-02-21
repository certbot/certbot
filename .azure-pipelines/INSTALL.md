# Configuring Azure Pipelines with Certbot

Let's begin. All pipelines are defined in `.azure-pipelines`. Currently there are two:
* `.azure-pipelines/main.yml` is the main one, executed on PRs for master, and pushes to master,
* `.azure-pipelines/advanced.yml` add installer testing on top of the main pipeline, and is executed for `test-*` branches, release branches, and nightly run for master.

Several templates are defined in `.azure-pipelines/templates`. These YAML files aggregate common jobs configuration that can be reused in several pipelines.

Unlike Travis, where CodeCov is working without any action required, CodeCov supports Azure Pipelines
using the coverage-bash utility (not python-coverage for now) only if you provide the Codecov repo token
using the `CODECOV_TOKEN` environment variable. So `CODECOV_TOKEN` needs to be set as a secured
environment variable to allow the main pipeline to publish coverage reports to CodeCov.

This INSTALL.md file explains how to configure Azure Pipelines with Certbot in order to execute the CI/CD logic defined in `.azure-pipelines` folder with it.
During this installation step, warnings describing user access and legal comitments will be displayed like this:
```
!!! ACCESS REQUIRED !!!
```

This document supposes that the Azure DevOps organization is named _certbot_, and the Azure DevOps project is also _certbot_.

## Useful links

* https://docs.microsoft.com/en-us/azure/devops/pipelines/yaml-schema?view=azure-devops&tabs=schema
* https://www.azuredevopslabs.com/labs/azuredevops/github-integration/
* https://docs.microsoft.com/en-us/azure/devops/pipelines/ecosystems/python?view=azure-devops

## Prerequisites

### Having a GitHub account

Use your GitHub user for a normal GitHub account, or a user that has administrative rights to the GitHub organization if relevant.

### Having an Azure DevOps account
- Go to https://dev.azure.com/, click "Start free with GitHub"
- Login to GitHub

```
!!! ACCESS REQUIRED !!!
Personal user data (email + profile info, in read-only)
```

- Microsoft will create a Live account using the email referenced for the GitHub account. This account is also linked to GitHub account (meaning you can log it using GitHub authentication)
- Proceed with account registration (birth date, country), add details about name and email contact

```
!!! ACCESS REQUIRED !!!
Microsoft proposes to send commercial links to this mail
Azure DevOps terms of service need to be accepted
```

_Logged to Azure DevOps, account is ready._

### Installing Azure Pipelines to GitHub

- On GitHub, go to Marketplace
- Select Azure Pipeline, and "Set up a plan"
- Select Free, then "Install it for free"
- Click "Complete order and begin installation"

```
!!! ACCESS !!!
Azure Pipeline needs RW on code, RO on metadata, RW on checks, commit statuses, deployments, issues, pull requests.
RW access here is required to allow update of the pipelines YAML files from Azure DevOps interface, and to
update the status of builds and PRs on GitHub side when Azure Pipelines are triggered.
Note however that no admin access is defined here: this means that Azure Pipelines cannot do anything with
protected branches, like master, and cannot modify the security context around this on GitHub.
Access can be defined for all or only selected repositories, which is nice.
```

- Redirected to Azure DevOps, select the account created in _Having an Azure DevOps account_ section.
- Select the organization, and click "Create a new project" (let's name it the same than the targeted github repo)
- The Visibility is public, to profit from 10 parallel jobs

```
!!! ACCESS !!!
Azure Pipelines needs access to the GitHub account (in term of being able to check it is valid), and the Resources shared between the GitHub account and Azure Pipelines.
```

_Done. We can move to pipelines configuration._

## Import an existing pipelines from `.azure-pipelines` folder

- On Azure DevOps, go to your organization (eg. _certbot_) then your project (eg. _certbot_)
- Click "Pipelines" tab
- Click "New pipeline"
- Where is your code?: select "__Use the classic editor__"

__Warning: Do not choose the GitHub option in Where is your code? section. Indeed, this option will trigger an OAuth
grant permissions from Azure Pipelines to GitHub in order to setup a GitHub OAuth Application. The permissions asked
then are way too large (admin level on almost everything), while the classic approach does not add any more
permissions, and works perfectly well.__

- Select GitHub in "Select your repository section", choose certbot/certbot in Repository, master in default branch.
- Click on YAML option for "Select a template"
- Choose a name for the pipeline (eg. test-pipeline), and browse to the actual pipeline YAML definition in the
  "YAML file path" input (eg. `.azure-pipelines/test-pipeline.yml`)
- Click "Save & queue", choose the master branch to build the first pipeline, and click "Save and run" button.

_Done. Pipeline is operational. Repeat to add more pipelines from existing YAML files in `.azure-pipelines`._

## Add a secret variable to a pipeline (like `CODECOV_TOKEN`)

__NB: Following steps suppose that you already setup the YAML pipeline file to
consume the secret variable that these steps will create as an environment variable.
For a variable named `CODECOV_TOKEN` consuming the variable `codecov_token`,
in the YAML file this setup would take the form of the following:
```
steps:
    - script: ./do_something_that_consumes_CODECOV_TOKEN  # Eg. `codecov -F windows`
      env:
        CODECOV_TOKEN: $(codecov_token)
```

To set up a variable that is shared between pipelines, follow the instructions
at
https://docs.microsoft.com/en-us/azure/devops/pipelines/library/variable-groups.
When adding variables to a group, don't forget to tick "Keep this value secret"
if it shouldn't be shared publicly.
