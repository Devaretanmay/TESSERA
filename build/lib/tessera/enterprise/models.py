from dataclasses import dataclass, field
from typing import Optional
from datetime import datetime
import uuid


@dataclass
class Tenant:
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:12])
    name: str = ""
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    settings: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "created_at": self.created_at,
            "settings": self.settings,
        }


class Role(str):
    ADMIN = "admin"
    SECURITY_ENGINEER = "security_engineer"
    VIEWER = "viewer"
    API_USER = "api_user"


class Permission(str):
    SCAN = "scan"
    CONFIGURE = "configure"
    VIEW = "view"
    ADMIN = "admin"


ROLE_PERMISSIONS = {
    Role.ADMIN: [Permission.SCAN, Permission.CONFIGURE, Permission.VIEW, Permission.ADMIN],
    Role.SECURITY_ENGINEER: [Permission.SCAN, Permission.CONFIGURE, Permission.VIEW],
    Role.VIEWER: [Permission.VIEW],
    Role.API_USER: [Permission.SCAN, Permission.VIEW],
}


def has_permission(role: Role, permission: Permission) -> bool:
    return permission in ROLE_PERMISSIONS.get(role, [])


@dataclass
class User:
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:12])
    tenant_id: str = ""
    role: Role = Role.VIEWER
    name: str = ""
    email: str = ""
    api_key_hash: Optional[str] = None
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    last_login: Optional[str] = None

    def can(self, permission: Permission) -> bool:
        return has_permission(self.role, permission)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "tenant_id": self.tenant_id,
            "role": self.role,
            "name": self.name,
            "email": self.email,
            "created_at": self.created_at,
            "last_login": self.last_login,
        }


@dataclass
class APIKey:
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:16])
    tenant_id: str = ""
    user_id: str = ""
    key_hash: str = ""
    name: str = ""
    permissions: list[Permission] = field(default_factory=list)
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    expires_at: Optional[str] = None
    last_used: Optional[str] = None

    def is_expired(self) -> bool:
        if not self.expires_at:
            return False
        return datetime.fromisoformat(self.expires_at) < datetime.utcnow()

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "tenant_id": self.tenant_id,
            "user_id": self.user_id,
            "name": self.name,
            "permissions": self.permissions,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "last_used": self.last_used,
        }


@dataclass
class AuditLog:
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:12])
    tenant_id: str = ""
    user_id: str = ""
    action: str = ""
    resource: str = ""
    details: dict = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    ip_address: Optional[str] = None


class TenantContext:
    def __init__(self, tenant_id: str, user_id: str, role: Role):
        self.tenant_id = tenant_id
        self.user_id = user_id
        self.role = role

    def can(self, permission: Permission) -> bool:
        return has_permission(self.role, permission)
