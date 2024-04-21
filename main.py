import os
import keycloak
import logging
import time
import sched
import string
import traceback
from mailjet_rest import Client
from keycloak import KeycloakAdmin
from dotenv import load_dotenv
from typing import Dict, Tuple

load_dotenv()

logging.basicConfig(level=logging.WARN, format="%(asctime)s - %(levelname)s - %(message)s")
LOGGER = logging.getLogger(__name__)

PASSWORD_CHARS = string.ascii_letters + string.digits + string.punctuation

keycloak_connection = keycloak.KeycloakOpenIDConnection(
    server_url=os.environ.get("KEYCLOAK_SERVER_URL"),
    client_id=os.environ.get("KEYCLOAK_CLIENT_ID"),
    realm_name=os.environ.get("KEYCLOAK_REALM"),
    client_secret_key=os.environ.get("KEYCLOAK_CLIENT_SECRET"),
    user_realm_name=os.environ.get("KEYCLOAK_USER_REALM_NAME"),
    username=os.environ.get("KEYCLOAK_USERNAME"),
    password=os.environ.get("KEYCLOAK_PASSWORD"),
    verify=True
)
KEYCLOAK_ADMIN = KeycloakAdmin(connection=keycloak_connection)
MAILJET = Client(auth=(os.environ.get("MJ_APIKEY_PUBLIC"), os.environ.get("MJ_APIKEY_PRIVATE")), version="v3.1")

POLL_INTERVAL_IN_MS = os.environ.get("POLLING_INTERVAL")
POLL_INTERVAL_IN_MS = int(POLL_INTERVAL_IN_MS) if POLL_INTERVAL_IN_MS is not None else 1000
REQUIRED_ACTIONS = os.environ.get("NEW_REQUIRED_ACTIONS").split(",") if os.environ.get(
    "NEW_REQUIRED_ACTIONS") is not None else []


def secure_password_gen(length: int = 16) -> str:
    # At least one uppercase, one lowercase, one digit and one punctuation
    password = ""
    while not (any(x.isupper() for x in password) and any(x.islower() for x in password) and any(
            x.isdigit() for x in password) and any(x in string.punctuation for x in password)):
        password = ''.join([PASSWORD_CHARS[ord(os.urandom(1)) % len(PASSWORD_CHARS)] for _ in range(length)])
    return password


def update_user_password(user, password: str):
    KEYCLOAK_ADMIN.set_user_password(user['id'], password=password, temporary=True)


def get_email_template(name: str, placeholders: Dict[str, str]) -> Tuple[str, str]:
    with open(f"./email_templates/{name.upper()}.txt", "r") as f:
        content = f.read()
        f.close()
    subject = content.split("\n")[0]
    content = content.replace(subject, "")
    subject = subject.replace("SUBJECT: ", "")
    for placeholder in placeholders:
        content = content.replace(placeholder, placeholders[placeholder])
    return content, subject


def send_email(template_name: str, user):
    password = secure_password_gen()
    email_template, subject_line = get_email_template(template_name, {"%username%": user["username"],
                                                                      "%email%": user["email"],
                                                                      "%first_name%": user["firstName"],
                                                                      '%password%': password})
    update_user_password(user, password)
    return {
        "From": {
            "Email": "auth@bytebolt.media",
            "Name": "ByteBolt"
        },
        "To": [
            {
                "Email": user["email"],
                "Name": user["username"]
            }
        ],
        "Subject": subject_line,
        "TextPart": "",
        "HTMLPart": email_template
    }


def poll_for_users(scheduler):
    scheduler.enter(POLL_INTERVAL_IN_MS / 1000, 1, poll_for_users, (scheduler,))
    users = KEYCLOAK_ADMIN.get_users({})
    users = [user for user in users if isinstance(user, dict)]
    users = [user for user in users if "invitation_sent" not in user["attributes"]]
    users = [user for user in users if (user["createdTimestamp"] / 1000) >=
             (time.time() - (
                     2 * (POLL_INTERVAL_IN_MS / 1000)))]  # Anyone joined in the last 2*POLL_INTERVAL_IN_MS seconds
    if len(users) == 0:
        LOGGER.info("No new users found")
        return
    else:
        LOGGER.info(f"Found {len(users)} new users")

    data = {"Messages": []}
    for user in users:
        data["Messages"].append(send_email("new_user", user))

    result = MAILJET.send.create(data=data)
    emails = [user["email"] for user in users]
    if result.status_code != 200:
        LOGGER.error(f"Failed to send email to {emails}")
    else:
        LOGGER.info(f"Email sent to {emails}")
        for user in users:
            # For some reason lastName and firstName are being wiped so we'll force an update here.
            firstName = user["firstName"]
            lastName = user["lastName"] if "lastName" in user.keys() else ""
            response = KEYCLOAK_ADMIN.update_user(user['id'],
                                                  {"attributes": {os.environ.get(
                                                      "KEYCLOAK_INVITATION_SENT_ATTRIBUTE_ID"):
                                                                      True},
                                                   "firstName": firstName,
                                                   "lastName": lastName})
            # KEYCLOAK_ADMIN.send_update_account(user['id'], REQUIRED_ACTIONS)


def main():
    app_scheduler = sched.scheduler(time.time, time.sleep)
    app_scheduler.enter(POLL_INTERVAL_IN_MS / 1000, 1, poll_for_users, (app_scheduler,))
    app_scheduler.run()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        LOGGER.info("Exiting...")
        exit(0)
    except Exception as e:
        LOGGER.error(e)
        LOGGER.error(traceback.format_exc())
        exit(1)
