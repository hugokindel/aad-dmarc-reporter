#!/usr/bin/env python3
# coding: utf-8

import io
import os
import re
import gzip
import msal
import json
import boto3
import base64
import logging
import zipfile
import argparse
import requests
from lxml import etree
from datetime import timedelta, datetime


def load_attachment(name, content, to_base64=True):
    """
    Prepares an attachment to be sent in a mail through the Graph API.

    Parameters
    ----------
    name : str
        Name of the attachment.
    content : bytes
        Content of the attachment. It should be encoded in UTF-8.
    to_base64 : bool, optional
        The content needs to be base64 encoded, if it is already done, you can define this parameter to `False`.

    Returns
    -------
    dict
        A dictionary containing the attachment data.
    """
    if to_base64:
        content = base64.b64encode(content).decode("utf-8")

    data = {
        "@odata.type": "#microsoft.graph.fileAttachment",
        "name": name,
        "contentBytes": content
    }

    return data


def fatal_error(response=None, code=1):
    """
    Logs a fatal error and exits the program with a given error code.

    Parameters
    ----------
    response : Response, optional
        Response object from the Graph API.
    code : int, optional
        Error code to exit the program with.

    Returns
    -------
    int
        The error code.
    """
    if response:
        logging.critical(response.json())
        logging.critical("Make sure the app registration has the following applicative permissions: "
                         "`AuditLog.Read.All`, `Directory.Read.All` and `Mail.Send`.")

    return code


# noinspection PyUnusedLocal
def main(event, context):
    """
    Analyzes all the DMARC reports from a given mailbox inside an Azure AD tenant and sends a mail to the domain
    owner(s) through emails with the details of the failures inside a .csv file.

    Parameters
    ----------
    event: dict
        The event which triggered this function.
    context: Context
        The context of the function.

    Returns
    -------
    int
        The error code.
    """
    parser = argparse.ArgumentParser(
        description="Tool to analyze failures from DMARC reports and send a mail to the domain owner(s) with the "
        "details of the failures.\n"
        "\n"
        "You need to define multiple values through environment variables or a JSON config file:\n"
        "- AZURE_CLIENT_ID:                Azure application's client ID.\n"
        "- AZURE_CLIENT_SECRET:            Azure application's client secret.\n"
        "- AZURE_TENANT_ID:                Azure environment tenant ID.\n"
        "- AZURE_USER_ID:                  Azure user ID which will be analyzed.\n"
        "- AWS_SECRETSMANAGER_REGION:      AWS region where the secrets are stored.\n"
        "- AWS_SECRETSMANAGER_SECRET_ID:   AWS secret ID where the secrets are stored.\n"
        "- NOTIFICATION_TARGETS:           Targets (mail addresses) to which notifications emails will be sent.\n"
        "- EXCLUDED_RECEIVER_DOMAINS:      Receiver domains which will be excluded from the analysis (in regex).\n"
        "- EXCLUDED_SENDER_DOMAINS:        Sender domains which will be excluded from the analysis (in regex).\n"
        "- EXCLUDED_SENDER_IP_ADDRESSES:   IP addresses from the analysis (in regex).",
        formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("-c", "--config", help="Path to the config file containing the execution configuration ("
                                               "including secrets).")
    parser.add_argument("--no-mail", help="Deactivates the mail sending feature.", action="store_true")
    args = parser.parse_args()

    logging.getLogger().setLevel(logging.INFO)

    # First, search for each variable through the environment variables.
    azure_client_id = os.environ.get("AZURE_CLIENT_ID", "")
    azure_client_secret = os.environ.get("AZURE_CLIENT_SECRET", "")
    azure_tenant_id = os.environ.get("AZURE_TENANT_ID", "")
    azure_user_id = os.environ.get("AZURE_USER_ID", "")
    aws_secretsmanager_region = os.environ.get("AWS_SECRETSMANAGER_REGION")
    aws_secretsmanager_secret_id = os.environ.get("AWS_SECRETSMANAGER_SECRET_ID")
    notification_targets = os.environ.get("NOTIFICATION_TARGETS", "")
    receiver_domains_exclusion_list = os.environ.get("EXCLUDED_RECEIVER_DOMAINS", [])
    sender_domains_exclusion_list = os.environ.get("EXCLUDED_SENDER_DOMAINS", [])
    sender_ip_addresses_exclusion_list = os.environ.get("EXCLUDED_SENDER_IP_ADDRESSES", [])

    # Then, look through the config file if it is provided and the variables are not defined.
    if args.config:
        config_file = open(args.config, "r", encoding="utf-8")
        config_json = json.load(config_file)
        config_file.close()

        # noinspection DuplicatedCode
        if not azure_client_id and "AZURE_CLIENT_ID" in config_json:
            azure_client_id = config_json["AZURE_CLIENT_ID"]
        if not azure_client_secret and "AZURE_CLIENT_SECRET" in config_json:
            azure_client_secret = config_json["AZURE_CLIENT_SECRET"]
        if not azure_tenant_id and "AZURE_TENANT_ID" in config_json:
            azure_tenant_id = config_json["AZURE_TENANT_ID"]
        if not azure_user_id and "AZURE_USER_ID" in config_json:
            azure_user_id = config_json["AZURE_USER_ID"]
        if not aws_secretsmanager_region and "AWS_SECRETSMANAGER_REGION" in config_json:
            aws_secretsmanager_region = config_json["AWS_SECRETSMANAGER_REGION"]
        if not aws_secretsmanager_secret_id and "AWS_SECRETSMANAGER_SECRET_ID" in config_json:
            aws_secretsmanager_secret_id = config_json["AWS_SECRETSMANAGER_SECRET_ID"]
        # noinspection DuplicatedCode
        if not notification_targets and "NOTIFICATION_TARGETS" in config_json:
            notification_targets = config_json["NOTIFICATION_TARGETS"]
        if not receiver_domains_exclusion_list and "EXCLUDED_RECEIVER_DOMAINS" in config_json:
            receiver_domains_exclusion_list = config_json["EXCLUDED_RECEIVER_DOMAINS"]
        if not sender_domains_exclusion_list and "EXCLUDED_SENDER_DOMAINS" in config_json:
            sender_domains_exclusion_list = config_json["EXCLUDED_SENDER_DOMAINS"]
        if not sender_ip_addresses_exclusion_list and "EXCLUDED_SENDER_IP_ADDRESSES" in config_json:
            sender_ip_addresses_exclusion_list = config_json["EXCLUDED_SENDER_IP_ADDRESSES"]

    # Finally, look through AWS Secrets Manager if the variables are not defined.
    if aws_secretsmanager_region and aws_secretsmanager_secret_id:
        session = boto3.session.Session()
        client = session.client(service_name="secretsmanager", region_name=aws_secretsmanager_region)

        try:
            secrets = json.loads(client.get_secret_value(SecretId=aws_secretsmanager_secret_id)["SecretString"])

            # noinspection DuplicatedCode
            if not azure_client_id and "AZURE_CLIENT_ID" in secrets:
                azure_client_id = secrets["AZURE_CLIENT_ID"]
            if not azure_client_secret and "AZURE_CLIENT_SECRET" in secrets:
                azure_client_secret = secrets["AZURE_CLIENT_SECRET"]
            if not azure_tenant_id and "AZURE_TENANT_ID" in secrets:
                azure_tenant_id = secrets["AZURE_TENANT_ID"]
            if not azure_user_id and "AZURE_USER_ID" in secrets:
                azure_user_id = secrets["AZURE_USER_ID"]
            # noinspection DuplicatedCode
            if not notification_targets and "NOTIFICATION_TARGETS" in secrets:
                notification_targets = secrets["NOTIFICATION_TARGETS"]
            if not receiver_domains_exclusion_list and "EXCLUDED_RECEIVER_DOMAINS" in secrets:
                receiver_domains_exclusion_list = secrets["EXCLUDED_RECEIVER_DOMAINS"]
            if not sender_domains_exclusion_list and "EXCLUDED_SENDER_DOMAINS" in secrets:
                sender_domains_exclusion_list = secrets["EXCLUDED_SENDER_DOMAINS"]
            if not sender_ip_addresses_exclusion_list and "EXCLUDED_SENDER_IP_ADDRESSES" in secrets:
                sender_ip_addresses_exclusion_list = secrets["EXCLUDED_SENDER_IP_ADDRESSES"]
        except Exception as error:
            logging.critical(error)

    if not azure_client_id or not azure_client_secret or not azure_tenant_id or not azure_user_id:
        logging.critical("You need to specify a client ID (AZURE_CLIENT_ID), client secret (AZURE_CLIENT_SECRET), "
                         "tenant ID (AZURE_TENANT_ID) and user ID (AZURE_USER_ID) to connect to Azure AD.")
    if not notification_targets:
        logging.warning("You need to provide notification target(s) (NOTIFICATION_TARGETS) as receivers to "
                        "successfully send a mail.")

    if not azure_client_id or not azure_client_secret or not azure_tenant_id or not azure_user_id:
        return fatal_error()

    # Build notification targets.
    notification_targets = notification_targets.split(",")

    # Build exclusion patterns.
    receiver_domains_exclusion_patterns = []
    sender_domains_exclusion_patterns = []
    ip_addresses_exclusion_patterns = []

    if receiver_domains_exclusion_list:
        receiver_domains_exclusion_list = receiver_domains_exclusion_list.split(",")
        for exclusion in receiver_domains_exclusion_list:
            receiver_domains_exclusion_patterns.append(re.compile(exclusion))

    if sender_domains_exclusion_list:
        sender_domains_exclusion_list = sender_domains_exclusion_list.split(",")
        for exclusion in sender_domains_exclusion_list:
            sender_domains_exclusion_patterns.append(re.compile(exclusion))

    if sender_ip_addresses_exclusion_list:
        sender_ip_addresses_exclusion_list = sender_ip_addresses_exclusion_list.split(",")
        for exclusion in sender_ip_addresses_exclusion_list:
            ip_addresses_exclusion_patterns.append(re.compile(exclusion))

    authority = f"https://login.microsoftonline.com/{azure_tenant_id}"
    scopes = ["https://graph.microsoft.com/.default"]
    graph_url = "https://graph.microsoft.com/v1.0"

    # Connects to MSAL API.
    app = msal.ConfidentialClientApplication(client_id=azure_client_id, client_credential=azure_client_secret,
                                             authority=authority)

    # Check for a suitable token in cache.
    token_request = app.acquire_token_silent(scopes, account=None)

    # If there is no suitable token in cache, tries to get a new one from AAD.
    if not token_request:
        token_request = app.acquire_token_for_client(scopes=scopes)

    # If we did not successfully get a suitable token, prints the error and exits.
    if "access_token" not in token_request:
        logging.critical(token_request.get("error"))
        logging.critical(token_request.get("error_description"))
        logging.critical(token_request.get("correlation_id"))
        return fatal_error()

    # Prepares the token for the next requests.
    token = {"Authorization": f"Bearer {token_request['access_token']}"}

    # Get all unread mails of a given mailbox.
    r = requests.get(f"{graph_url}/users/{azure_user_id}/messages?$filter=isRead eq false&$top=999", headers=token)
    if not r.ok:
        return fatal_error(r)

    mails = r.json()["value"]

    logging.info(f"There is {len(mails)} unread mails.")

    if len(mails) == 0:
        return 0

    csv = "File;Receiver Domain;Sender Domain;Sender IP Address;SPF Status;DKIM Status;DMARC Disposition;Comment"
    files_to_include = []
    num_failures = 0
    for mail in mails:
        has_failures = False

        # Get all attachments of a given mail.
        r = requests.get(f"{graph_url}/users/{azure_user_id}/messages/{mail['id']}/attachments", headers=token)
        if not r.ok:
            return fatal_error(r)

        attachments = r.json()["value"]
        for attachment in attachments:
            decoded_bytes = io.BytesIO(base64.b64decode(attachment["contentBytes"]))

            # Decompress the attachment (it has to be a .zip or .gz).
            if attachment["name"].endswith(".zip"):
                filename = attachment["name"][0: -4]
                compressed_content = zipfile.ZipFile(decoded_bytes)
                decompressed_content = compressed_content.read(compressed_content.infolist()[0])
                tree = etree.fromstring(decompressed_content)
            elif attachment["name"].endswith(".gz"):
                filename = attachment["name"][0: -3]
                decompressed_content = gzip.GzipFile(fileobj=decoded_bytes, mode="rb").read()
                tree = etree.fromstring(decompressed_content)
            else:
                logging.fatal(f"Unknown attachment type: {attachment['name']}")
                return fatal_error()

            if not filename.endswith(".xml"):
                filename += ".xml"

            dispositions = tree.findall(".//{*}disposition")
            for disposition in dispositions:
                if disposition.text == "quarantine" or disposition.text == "rejected":
                    excluded = False

                    receiver_domain = filename.split('!')[0]
                    sender_domain = disposition.find('../../../auth_results/spf/domain').text
                    sender_ip_address = disposition.find('../../source_ip').text
                    spf_status = disposition.find('../spf').text
                    dkim_status = disposition.find('../dkim').text

                    # Check for exclusion patterns.
                    for pattern in receiver_domains_exclusion_patterns:
                        if pattern.search(receiver_domain):
                            excluded = True
                            break

                    if not excluded:
                        for pattern in sender_domains_exclusion_patterns:
                            if pattern.search(sender_domain):
                                excluded = True
                                break

                    if not excluded:
                        for pattern in ip_addresses_exclusion_patterns:
                            if pattern.search(sender_ip_address):
                                excluded = True
                                break

                    if excluded:
                        continue

                    if not has_failures:
                        files_to_include.append((filename, decompressed_content))

                    has_failures = True
                    num_failures += 1
                    csv += f"\n{filename};" \
                           f"{receiver_domain};" \
                           f"{sender_domain};" \
                           f"{sender_ip_address};" \
                           f"{spf_status};" \
                           f"{dkim_status};" \
                           f"{disposition.text};"

        # Marks the mail as read.
        r = requests.patch(f"{graph_url}/users/{azure_user_id}/messages/{mail['id']}", headers=token,
                           json={"isRead": True})
        if not r.ok:
            return fatal_error(r)

    message = f"There has been {num_failures} failures in DMARC reports."

    logging.info(message)
    if num_failures > 0:
        logging.info(csv)

    # Sends a mail if there are failures.
    if num_failures > 0 and not args.no_mail and azure_user_id and notification_targets:
        message += "\nPlease find the details in the attached CSV file."

        reports = [load_attachment(f"dmarc-report_{(datetime.utcnow().date() - timedelta(days=1)).strftime('%Y-%m-%d')}"
                                   f".csv",
                   csv.encode("utf-8"))] + [load_attachment(x, y) for (x, y) in files_to_include]

        # Prepares the mail.
        email_msg = {
            "Message": {
                "ToRecipients": [{"EmailAddress": {"Address": x}} for x in notification_targets],
                "Subject": "Failures in DMARC Report",
                "Body": {
                    "ContentType": "Text",
                    "Content": f"{message}"
                },
                "Importance": "Normal",
                "Attachments": reports
            },
            "SaveToSentItems": "true"
        }

        # Sends the mail.
        r = requests.post(f"{graph_url}/users/{azure_user_id}/sendMail", headers=token, json=email_msg)
        if not r.ok:
            return fatal_error(r)

        logging.info("Mail sent.")

    return 0


if __name__ == '__main__':
    exit(main({}, None))
