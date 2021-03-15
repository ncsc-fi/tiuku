# Tiuku

Tiuku is a tool for scanning various kinds of systems and environments for security related information and displaying the results in a browser-based user interface. It can also detect and highlight some issues automatically. Both the data collection scripts and the user interface can be downloaded and run completely offline, so they also work in air-gapped environments.

![Screenshot](docs/images/screenshot.png?raw=true)

Tiuku differs from other security scanning tools in the following ways:

* It supports multiple platforms and provides a unified user experience across all of them. Whether you assess a SaaS platform like M365, an Active Directory domain, or a single Linux server, the tool works the same way and provides a similar graphical user interface.

* It is simple to run. The tool has no dependencies beyond what's provided by modern operating systems, and there are no configuration files or command line parameters to worry about.

* It is designed to not overwhelm the user. Only information that is deemed relevant to most users and environments is displayed.

All in all, it provides a quick and easy way to get a security overview across the many different platforms that a company might use. For systems administrators, it is a simpler alternative to platform-specific security scanners that all work in different ways. For security specialists, it can be the first step in an assessment to get the lay of the land before in-depth exploration using more specialized tools.

![Tests](workflows/CI/badge.svg)

![Architecture](docs/images/architecture.png?raw=true "Architecture")

## Getting started

1. Download the ZIP file for [the latest release](releases/latest) (named `tiuku-release-<version>.zip`).

   You may have to disable your antivirus program to download the file. While it's not malicious, it collects security-related data from your environment in a way that an antivirus may consider suspicious.

2. Extract the ZIP file.

3. Double-click on `index.html` to open the user interface

4. Pick a collector from the `collectors` directory and follow the instructions in its `README.md` to run it.

5. Drag and drop the `.json` file created by the collector onto the user interface.

## Reporting problems

1. Check [the existing issues](issues?q=is%3Aissue) in case your problem has already been reported.

2. If there's no existing issue for the problem, please create a new issue describing:

   * What you did, in enough detail for someone else to follow the steps to reproduce the issue.

   * What you expected to happen.

   * What actually happened. Include all error messages in full.

   * Any details about your environment (the operating system, PowerShell or Python version, etc.) that might be relevant in order to reproduce the issue.

## Other documents
- [Development guide](docs/development.md) 
