from google.auth.transport.requests import AuthorizedSession
from google.auth.transport.requests import Request
from google.auth.credentials import Credentials
from google.oauth2.credentials import Credentials as UserCredentials
from google.oauth2.service_account import Credentials as SACredentials
from google_auth_oauthlib.flow import InstalledAppFlow
from pathlib import Path
from typing import Sequence

def get_new_authenticated_session(credentials: Credentials) -> AuthorizedSession:
    return AuthorizedSession(credentials, auth_request=Request())

def generate_user_credentials_from_client_secrets_file(credentials_path: Path, scopes: Sequence[str], **options) -> UserCredentials:
    if not credentials_path.is_file():
        raise FileNotFoundError("Unable to create user credentials without client secret file.")
    if scopes is None or len(scopes) == 0:
        raise Exception("No scope specified.")
    auth_flow = InstalledAppFlow.from_client_secrets_file(str(credentials_path), scopes)
    if "console" in options and options["console"]:
        return auth_flow.run_console(**options)
    else:
        return auth_flow.run_local_server(**options)

def generate_sa_credentials_from_service_account_file(service_account_path: Path, scopes: Sequence[str], **options) -> SACredentials:
    if not service_account_path.is_file():
        raise FileNotFoundError("Unable to create service account credentials without service account file.")
    if scopes is None or len(scopes) == 0:
        raise Exception("No scope specified.")
    return SACredentials.from_service_account_file(str(service_account_path), **options)