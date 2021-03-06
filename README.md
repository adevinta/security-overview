# Security Overview

`Security Overview` is a library used to generate detailed reports. It receives as
input an scan-id, a team name and then generates an `html` email containing some
summarized information about the scan, which links to a full report dashboard
containing detailed information about the scan. This dashboard is automatically
uploaded to a `S3` bucket.

# CLI

The cli provides functionality to test the report generation.

To install ,after cloning the repo, execute
```
go install ./...
```



It works by supporting three scenarios:

1. Generate and optionally upload a report.

    At the root of the report execute:
   ```
   vulcan-security-overview -config _config/dev.toml -scan-id scanid -team-name team-name
   ```
   The config param contains at path to a config file, there are examples of this config files at the dir: ```config```

2. Regenerate a report

    For modifying the look and feel or the javascript of the reports is useful to
    have a way to regenerate a report.
    The regenerate command takes a json file, generated by the command explained at the previous section,
    and regenerates the html and all the assets: javascript, css, etc... containing the full report

    To regenerate command execute:

    ```
    vulcan-security-overview -regen .localtest/test-report.json -resources _resources/ -presources _public_resources/ --assetsurl https://example.com/assets  -output .localtest/reports

    ```
3. Generate a full report from a file with a check report.

   This scenario is useful when adjusting the output of a check.
   This command takes, apart from the config file, a parameter pointing to a file that contains a check report.
   It generates and uploads to s3 a full report with the findings of that check.

   Example of the command:
   ```
    vulcan-security-overview -config "security-overview.toml" -check check_report.json
   ```
