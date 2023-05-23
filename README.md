# DMARC Reporter

Tool to analyze failures from DMARC reports and send a mail to the domain owner(s) with the details of the failures.  
Disclaimer: For now, it only works with mailboxes set up in Azure Active Directory.

## How to use

- Install dependencies: `pip3 install msal requests lxml boto3`.
- Run the following command: `./src/dmarc_reporter.py`.

It will ask you to fill a few environment variables or to provide a configuration file containing secrets to make the
connection with the Active Directory through the Graph API.

## How to deploy

- Make sure `awscli` and `serverless` (through `npm`) are installed.
- Configure your credentials with `aws configure`.
- Run `serverless deploy`.

## Dependencies

- [MSAL](https://github.com/AzureAD/microsoft-authentication-library-for-python)
- [Requests](https://pypi.org/project/requests/)
- [LXML](https://pypi.org/project/lxml/)
- [Boto3](https://pypi.org/project/boto3/)
