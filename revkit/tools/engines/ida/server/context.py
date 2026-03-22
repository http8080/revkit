from dataclasses import dataclass


@dataclass
class ServerContext:
    config: dict
    config_path: str
    instance_id: str
    binary_path: str
    idb_path: str
    port: int = 0
    auth_token: str = ""
    registry_path: str = ""
    log_path: str = ""
