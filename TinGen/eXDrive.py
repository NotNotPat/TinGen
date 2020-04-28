from google.auth.transport.requests import AuthorizedSession
from requests import Session
from google.auth.transport.requests import Request
from google.auth.credentials import Credentials
from google.oauth2.credentials import Credentials as UserCredentials
from google.oauth2.service_account import Credentials as SACredentials
from google_auth_oauthlib.flow import InstalledAppFlow
from pathlib import Path
from typing import Sequence
from abc import ABCMeta
from abc import abstractmethod
from requests import Response


class AuthHelpers(object, metaclass=ABCMeta):
    @abstractmethod
    def __init__(self):
        super().__init__()

    @staticmethod
    def generate_sa_credentials_from_service_account_file(
        service_account_path: Path,
        scopes: Sequence[str],
        **options
    ) -> SACredentials:
        if not service_account_path.is_file():
            raise FileNotFoundError("Unable to create service account credentials without service account file.")
        if scopes is None or len(scopes) == 0:
            raise Exception("No scope specified.")
        return SACredentials.from_service_account_file(str(service_account_path), **options)

    @staticmethod
    def generate_user_credentials_from_client_secrets_file(
        credentials_path: Path,
        scopes: Sequence[str],
        **options
    ) -> UserCredentials:
        if not credentials_path.is_file():
            raise FileNotFoundError("Unable to create user credentials without client secret file.")
        if scopes is None or len(scopes) == 0:
            raise Exception("No scope specified.")
        auth_flow = InstalledAppFlow.from_client_secrets_file(str(credentials_path), scopes)
        if "console" in options and options["console"]:
            return auth_flow.run_console(**options)
        else:
            return auth_flow.run_local_server(**options)

    @staticmethod
    def get_new_authenticated_session(
        credentials: Credentials
    ) -> AuthorizedSession:
        return AuthorizedSession(credentials, auth_request=Request())


class AbstractService(object, metaclass=ABCMeta):
    @abstractmethod
    def __init__(self, session: Session, service_slug: str, service_ver_num: str):
        super().__init__()
        self.SERVICE_URI = f"https://www.googleapis.com/{service_slug}/{service_ver_num}"
        self.session = session


class AbstractDriveV3Service(AbstractService):
    @abstractmethod
    def __init__(self, session:Session):
        super().__init__(session, service_slug="drive", service_ver_num="v3")

    @abstractmethod
    def list_all(self, folder_id:str, include_trashed:bool=False, nextPageToken=None, query_list:Sequence[str]=[], fields:Sequence[str]=[]) -> Response:
        params = {}
        if f"'{folder_id}' in parents" not in query_list:
            query_list.append(f"'{folder_id}' in parents")
        if not include_trashed and "trashed = false" not in query_list:
            query_list.append("trashed = false")
        if len(query_list) > 0:
            params.update({"q": " and ".join(query_list)})
        if nextPageToken is not None:
            params.update({"pageToken": nextPageToken})
        params.update({"supportsAllDrives": True, "pageSize": 1000})
        return self.session.request("GET", f"{self.SERVICE_URI}/files", params=params)

    @abstractmethod
    def list_folders(self, folder_id:str, include_trashed:bool=False, nextPageToken=None, query_list:Sequence[str]=[], fields:Sequence[str]=[]) -> Response:
        if "mimeType = 'application/vnd.google-apps.folder'" not in query_list:
            query_list.append("mimeType = 'application/vnd.google-apps.folder'")
        self.list_all(folder_id, include_trashed=include_trashed, nextPageToken=nextPageToken, query_list=query_list, fields=fields)

    @abstractmethod
    def list_files(self, folder_id: str, include_trashed: bool=False, nextPageToken=None, query_list:Sequence[str]=[], fields:Sequence[str]=[]) -> Response:
        super().list_files(folder_id, include_trashed=include_trashed, query_list=query_list, fields=fields)
        if "mimeType != 'application/vnd.google-apps.folder'" not in query_list:
            query_list.append("mimeType = 'application/vnd.google-apps.folder'")
        self.list_all(folder_id, include_trashed=include_trashed, nextPageToken=nextPageToken, query_list=query_list, fields=fields)


class AuthenticatedDriveV3Service(AbstractDriveV3Service):
    def __init__(self, credentials: Credentials):
        super().__init__(AuthHelpers.get_new_authenticated_session(credentials), service_slug="drive", service_ver_num="v3")

    def list_all(self, folder_id:str, include_trashed:bool=False, nextPageToken=None, query_list:Sequence[str]=[], fields:Sequence[str]=[]) -> Response:
        return super().list_all(folder_id, include_trashed=include_trashed, nextPageToken=nextPageToken, query_list=query_list, fields=fields)

    def list_folders(self, folder_id: str, include_trashed: bool=False, nextPageToken=None, query_list:Sequence[str]=[], fields:Sequence[str]=[]) -> Response:
        return super().list_folders(folder_id, include_trashed=include_trashed, nextPageToken=nextPageToken, query_list=query_list, fields=fields)

    def list_files(self, folder_id: str, include_trashed: bool=False, nextPageToken=None, query_list:Sequence[str]=[], fields:Sequence[str]=[]) -> Response:
        return super().list_files(folder_id, include_trashed=include_trashed, nextPageToken=nextPageToken, query_list=query_list, fields=fields)

    def empty_trash(self):
        return self.session.request("DELETE", f"{self.SERVICE_URI}/files/trash") 


class UnauthenticatedDriveV3Service(AbstractDriveV3Service):
    def __init__(self):
        super().__init__(Session())