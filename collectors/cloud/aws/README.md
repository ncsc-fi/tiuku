# AWS Collector

*Note: This collector is a proof of concept in very early stages of development!*

Collects data from an AWS account.

## Prerequisites

This proof-of-concept collector requires the installation of some external dependencies:

    pip3 install -r requirements.txt
    
You also need to configure AWS access keys either by [configuring the AWS CLI](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-quickstart.html) or setting the environment variables `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, and `AWS_REGION`.
    
## Usage

Run `main.py`:

    python3 main.py
