# Configuring Azure Pipelines with Certbot

Let's begin. All pipelines are defined in `.azure-pipelines`. Currently there are two:
* `.azure-pipelines/main.yml` is the main one, executed on PRs for master, and pushes to master,
* `.azure-pipelines/advanced.yml` add installer testing on top of the main pipeline, and is executed for `test-*` branches, release branches, and nightly run for master.

Several templates are defined in `.azure-pipelines/templates`. These YAML files aggregate common jobs configuration that can be reused in several pipelines.

Note that `CODECOV_TOKEN` secured environment variable needs to be set to allow the main pipeline to publish coverage reports to CodeCov.

This INSTALL.md file explains how to configure Azure Pipelines with Certbot in order to execute the CI/CD logic defined in `.azure-pipelines` folder with it.
During this installation step, warnings describing user access and legal comitments will be displayed like this:
```
!!! ACCESS REQUIRED !!!
```

This document suppose that the Azure DevOps organization is named _certbot_, and the Azure DevOps project is also _certbot_.

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
Azure Pipeline needs RW on code, RO on metadata, RW on checks, commit statuses, deployements, issues, pull requests.
Access can be defined for all or only selected repositories, which is nice.
```

- Redirected to Azure DevOps, select the account created in _Having an Azure DevOps account_ section.
- Select the organization, and click "Create a new project" (let's name it the same than the targetted github repo)
- The Visibility is public, to profit from 10 parallel jobs

```
!!! ACCESS !!!
Azure Pipelines needs access to the GitHub account (in term of beeing able to check it is valid), and the Resources shared between the GitHub account and Azure Pipelines.
```

_Done. We can move to pipelines configuration._

## Import an existing pipelines from `.azure-pipelines` folder

- On Azure DevOps, go to your organization (eg. _certbot_) then your project (eg. _certbot_)
- Click "Pipelines" tab
- Click "New pipeline"
- Where is your code? Select "GitHub"

```
!!! ACCESS !!!
Here comes the big requests:
- Admin access to webhooks and services (not the code)
- RO access on personal data (email + profile)
- RO + RW access to repositories (code, issue, PR, wiki, settings, webhooks, services, deploy keys, collaboration invites)
NB: Admin is not RW. Access concerns all repositories in the GitHub organization/user
```

- Select the repository (eg. certbot/certbot)
- Choose "Existing Azure Pipelines YAML file"
- Choose branch (`master` in the dropdown menu), and path (eg. /.azure-pipelines/pr.yml in the dropdown menu), click Continue
- Review the YAML, click Run

_Done. Pipeline is operational. Repeat to add more pipelines from existing YAML files in `.azure-pipelines`._

- (Bonus) Go again to Pipeline, select your pipline, button "..." and choose "Rename/Move": give to the pipeline a nice name!


## Add a secret variable to a pipeline (like `CODECOV_TOKEN`)

- On Azure DevOps, go to you organization, project, pipeline tab
- Select the pipeline, click "Edit" button, then click "Variables" button
- Set name (eg `codecov_token`), value, tick "Kep this value secret"
- In YAML, use something like to consume the secret as an enviroment variable
```
steps:
    - script: ./do_something_that_consumes_CODECOV_TOKEN  # Eg. `codecov -F windows`
      env:
        CODECOV_TOKEN: $(codecov_token)
```
