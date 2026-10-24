# IaC fixtures

- `project/`: deliberately misconfigured Terraform, Dockerfile, Kubernetes manifest and GitHub Actions workflow. Nothing here is deployed.
- `checkov-3.3.30.results.json`: real output of `checkov -d . --framework terraform,dockerfile,kubernetes,github_actions -o json --soft-fail --skip-download`
  (Checkov 3.3.30) run on `project/`, with the absolute checkout path replaced by `/fixture/project`.
