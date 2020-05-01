from abc import ABCMeta
from abc import abstractmethod
from google.auth.credentials import Credentials
from google.auth.transport.requests import AuthorizedSession
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials as UserCredentials
from google.oauth2.service_account import Credentials as SACredentials
from google_auth_oauthlib.flow import InstalledAppFlow
from pathlib import Path
from requests import Response
from requests import Session
from typing import Sequence
from json import load as json_deserialize
from json import dump as json_serialize
from json import JSONDecodeError
from uuid import uuid4 as uuid_generator


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
        client_id: str,
        client_secret: str,
        scopes: Sequence[str],
        **options
    ) -> UserCredentials:
        if scopes is None or len(scopes) == 0:
            raise Exception("No scope specified.")
        auth_flow = InstalledAppFlow.from_client_config({"installed": {"client_id": client_id, "client_secret": client_secret}})
        if "console" in options and options["console"]:
            return auth_flow.run_console(**options)
        else:
            return auth_flow.run_local_server(**options)

    @staticmethod
    def generate_user_credentials(
        client_secret_path: Path,
        scopes_needed: Sequence[str],
        **options
    ) -> UserCredentials:
        if not client_secret_path.is_file():
            raise FileNotFoundError(f"Client secret file {str(client_secret_path)} doesn't exist. Unable to proceed without valid client secret file.")
        else:
            with open(client_secret_path, "r") as client_secret_stream:
                try:
                    client_secret = json_deserialize(client_secret_stream)
                except JSONDecodeError:
                    raise FileNotFoundError(f"Client secret file {str(client_secret_path)} doesn't contain valid client secret JSON data. Unable to proceed without valid client secret file.")

        credentials = None
        token_path = options.get("token_path", None)

        if token_path is not None and token_path.is_file():
            try:
                with open(token_path, "r") as token_stream:
                    token = json_deserialize(token_stream)
                    if "refresh_token" in token.keys():
                        credentials = UserCredentials(
                            token.get("access_token", default=None),
                            refresh_token=token["refresh_token"],
                            client_id=client_secret["installed"]["client_id"],
                            client_secret=client_secret["installed"]["client_secret"]
                        )
            except JSONDecodeError:
                pass

        if credentials is None:
            credentials = AuthHelpers.generate_user_credentials_from_client_secrets_file(
                client_secret["installed"]["client_id"],
                client_secret["installed"]["client_secret"],
                scopes_needed,
                **options
            )

        if not credentials.valid:
            if not credentials.expired:
                credentials.refresh(Request())
            else:
                credentials = AuthHelpers.generate_user_credentials_from_client_secrets_file(
                    client_secret_path,
                    credentials.scopes,
                    **options
                )

        if not credentials.has_scopes(scopes_needed):
            credentials = AuthHelpers.generate_user_credentials_from_client_secrets_file(
                client_secret_path,
                scopes_needed.extend(credentials.scopes),
                **options
            )

        if token_path is not None:
            with open(token_path, "w") as token_stream:
                json_serialize({"access_token": credentials.token, "refresh_token": credentials.refresh_token}, token_stream)

        return credentials

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

    def list_all(self, folder_id: str, include_trashed: bool=False, page_token: str=None, query_list: Sequence[str]=[], fields: str="*") -> Response:
        params = {}
        if f"'{folder_id}' in parents" not in query_list:
            query_list.append(f"'{folder_id}' in parents")
        if not include_trashed and "trashed = false" not in query_list:
            query_list.append("trashed = false")
        if len(query_list) > 0:
            params.update({"q": " and ".join(query_list)})
        if page_token is not None:
            params.update({"pageToken": page_token})
        params.update({"supportsAllDrives": True, "pageSize": 1000, "fields": fields})
        return self.session.request("GET", f"{self.SERVICE_URI}/files", params=params)

    def list_folders(self, folder_id: str, include_trashed: bool=False, page_token: str=None, query_list: Sequence[str]=[], fields: str="*") -> Response:
        if "mimeType = 'application/vnd.google-apps.folder'" not in query_list:
            query_list.append("mimeType = 'application/vnd.google-apps.folder'")
        return self.list_all(folder_id, include_trashed=include_trashed, page_token=page_token, query_list=query_list, fields=fields)

    def list_files(self, folder_id: str, include_trashed: bool=False, page_token: str=None, query_list: Sequence[str]=[], fields: str="*") -> Response:
        if "mimeType != 'application/vnd.google-apps.folder'" not in query_list:
            query_list.append("mimeType != 'application/vnd.google-apps.folder'")
        return self.list_all(folder_id, include_trashed=include_trashed, page_token=page_token, query_list=query_list, fields=fields)

    def get_file_meta(self, file_id: str, fields: str="*") -> Response:
        return self.session.request("GET", f"{self.SERVICE_URI}/files/{file_id}", params={"alt": "json", "fields": fields, "supportsAllDrives": True})

    def download_file(self, file_id: str, hash_check: bool=True, chunk_size: int=1*1024*1024) -> Response:
        # TODO - Implementation
        pass

    def partial_download_file(self, file_id: str, total_size: int, range_start: int, chunk_size: int=1*1024*1024):
        # TODO - Implementation
        pass

class AuthDriveV3Service(AbstractDriveV3Service):
    def __init__(self, credentials: Credentials):
        super().__init__(AuthHelpers.get_new_authenticated_session(credentials))

    def empty_trash(self) -> Response:
        return self.session.request("DELETE", f"{self.SERVICE_URI}/files/trash") 

    def trash_file(self, file_id: str) -> Response:
        return self.session.request("PATCH", f"{self.SERVICE_URI}/files/{file_id}", data={"trashed": True}, params={"supportsAllDrives": True})

    def delete_file(self, file_id: str) -> Response:
        return self.session.request("DELETE", f"{self.SERVICE_URI}/files/{file_id}", params={"supportsAllDrives": True})

    def copy_file(self, file_id: str, parent_id: str=None, hash_check: bool=False, fields: str="*") -> Response:
        # TODO - Hash Checking
        data = {}
        if parent_id is not None:
            data.update({"parents": [parent_id]})
        return self.session.request("POST", f"{self.SERVICE_URI}/files/{file_id}/copy", params={"enforceSingleParent": True, "supportsAllDrives": True}, data=data)

    def copy_file_to_id(self, file_id: str, dest_file_id: str, hash_check: bool=False, fields: str="*") -> Response:
        # TODO - Hash Checking
        return self.session.request("POST", f"{self.SERVICE_URI}/files/{file_id}/copy", params={"enforceSingleParent": True, "supportsAllDrives": True}, data={"id": dest_file_id})

    def generate_ids(self, ids_to_generate: int, fields: str="*") -> Response:
        return self.session.request("GET", f"{self.SERVICE_URI}/files/generateIds", params={"count": ids_to_generate, fields: fields})

    def upload_file(self, file_path: Path, parent_id: str=None, hash_check: bool=True, chunk_size: int=1*1024*1024) -> Response:
        # TODO - Implementation
        pass

    def partial_upload_file(self, file_path: Path, parent_id: str=None, hash_check: bool=True, chunk_size: int=1*1024*1024) -> Response:
        # TODO - Implementation
        pass

    def update_existing_file(self, file_id: str, file_path: str, hash_check: bool=True, chunk_size: int=1*1024*1024) -> Response:
        # TODO - Implementation
        pass

    def create_permission(self, file_id: str, perm_role: str, perm_type: str, fields: str="*", allow_file_discovery: bool=False, email_address: str=None, domain: str=None) -> Response:
        if perm_type in ("user", "group") and email_address is None:
            # TODO - Exception Stuff
            raise Exception(f"")
 
        elif perm_type == "domain" and domain is None:
            # TODO - Exception Stuff
            raise Exception(f"")
 
        else:
            return self.session.request("POST", f"{self.SERVICE_URI}/files/{file_id}/permissions", params={"fields": fields, "enforceSingleParent": True, "supportsAllDrives": True}, data={"role": None, "type": None})

    def delete_permission(self, file_id: str, permission_id: str) -> Response:
        return self.session.request("DELETE", f"{self.SERVICE_URI}/files/{file_id}/permissions/{permission_id}", params={"supportsAllDrives": True})

    def get_permission(self, file_id: str, permission_id: str, fields: str="*") -> Response:
        return self.session.request("GET", f"{self.SERVICE_URI}/files/{file_id}/permissions/{permission_id}", params={"supportsAllDrives": True})

    def list_file_permissions(self, file_id: str, page_token: str=None, fields: str="*") -> Response:
        params = {"fields": fields, "supportsAllDrives": True}
        if page_token is not None:
            params.update({"pageToken": page_token})
        return self.session.request("GET", f"{self.SERVICE_URI}/files/{file_id}/permissions", params=params)

    def anyone_with_link_share_file(self, file_id: str, fields="*", allow_file_discovery=False) -> Response:
        return self.create_permission(file_id, "reader", "anyone", fields=fields, allow_file_discovery=allow_file_discovery)

    def create_shared_drive(self) -> Response:
        return self.session.request("POST", f"{self.SERVICE_URI}/drives", params={"requestId": uuid_generator()})

    def delete_shared_drive(self, drive_id: str) -> Response:
        return self.session.request("DELETE", f"{self.SERVICE_URI}/drives/{drive_id}")

    def get_shared_drive(self, drive_id: str) -> Response:
        return self.session.request("GET", f"{self.SERVICE_URI}/drives/{drive_id}")

    def hide_shared_drive(self, drive_id: str) -> Response:
        return self.session.request("POST", f"{self.SERVICE_URI}/drives/{drive_id}/hide")

    def unhide_shared_drive(self, drive_id: str) -> Response:
        return self.session.request("POST", f"{self.SERVICE_URI}/drives/{drive_id}/unhide")

    def list_shared_drives(self, page_token: str=None, query_list: Sequence[str]=[]) -> Response:
        params = {"pageSize": 100}
        if len(query_list) > 0:
            params.update({"q": " and ".join(query_list)})
        if page_token is not None:
            params.update({"pageToken": page_token})
        return self.session.request("GET", f"{self.SERVICE_URI}/drives", params=params)

    def change_shared_drive_name(self, drive_id: str, new_name: str) -> Response:
        return self.session.request("PATCH", f"{self.SERVICE_URI}/drives/{drive_id}", data={"name": new_name})


class DriveV3Service(AbstractDriveV3Service):
    def __init__(self):
        super().__init__(Session())