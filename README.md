![Snyk logo](https://snyk.io/style/asset/logo/snyk-print.svg)

***

# Snyk Code GitLab Ingestion
Python ingestion script for importing snyk code results into the GitLab vulnerability report.

Convert the Snyk CLI output to GitLab vulnerability data format. 

# Usage
- Basic
`snyk code test --json | python3 sast.py`

Example .gitlab-ci.yml running in a GitLab runner with Vuln Data & html report generated

```
snyk code:
  stage: test
  image:
    name: synk-image:latest
  script:
  - snyk auth ${SNYK_TOKEN}
  - snyk config set org="" && snyk config
  - snyk code test --json-file-output=snyk-code_report.json --json | python3 sast.py
  - snyk-to-html -i snyk-code_report.json -o snyk-code_${CI_PROJECT_NAME}.html
  artifacts:
    paths:
    - snyk-code_report.json
    - snyk-code_${CI_PROJECT_NAME}.html
    reports:
      sast: snyk-gl-code-scanning.json
```