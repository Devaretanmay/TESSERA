import hashlib
import secrets
from typing import Optional
from tessera.enterprise.models import APIKey, TenantContext, Role, Permission, User
from tessera.db.persistence import Persistence, UserRecord, APIKeyRecord


def generate_api_key() -> tuple[str, str]:
    raw = secrets.token_urlsafe(32)
    key_hash = hashlib.sha256(raw.encode()).hexdigest()
    return raw, key_hash


def hash_key(api_key: str) -> str:
    return hashlib.sha256(api_key.encode()).hexdigest()


class AuthStore:
    def __init__(self, db: Optional[Persistence] = None):
        self.db = db or Persistence()

    def create_api_key(
        self,
        tenant_id: str,
        user_id: str,
        name: str,
        permissions: list[Permission],
        expires_days: Optional[int] = None,
    ) -> tuple[APIKey, str]:
        raw_key, key_hash = generate_api_key()
        from datetime import datetime, timedelta

        expires = None
        if expires_days:
            expires = (datetime.utcnow() + timedelta(days=expires_days)).isoformat()

        key = APIKey(
            tenant_id=tenant_id,
            user_id=user_id,
            key_hash=key_hash,
            name=name,
            permissions=permissions,
            expires_at=expires,
        )
        
        record = APIKeyRecord(
            key_id=key.id,
            tenant_id=key.tenant_id,
            user_id=key.user_id,
            key_hash=key.key_hash,
            name=key.name,
            permissions=[str(p) for p in key.permissions],
            expires_at=key.expires_at,
            created_at=key.created_at,
            last_used=key.last_used
        )
        self.db.save_api_key(record)
        return key, raw_key

    def validate_key(self, api_key: str) -> Optional[APIKey]:
        key_hash = hash_key(api_key)
        record = self.db.get_api_key_by_hash(key_hash)
        if not record:
            return None
            
        key = APIKey(
            id=record.key_id,
            tenant_id=record.tenant_id,
            user_id=record.user_id,
            key_hash=record.key_hash,
            name=record.name,
            permissions=[Permission(p) for p in record.permissions],
            created_at=record.created_at,
            expires_at=record.expires_at,
            last_used=record.last_used
        )
        
        if key.is_expired():
            return None
            
        return key

    def revoke_key(self, key_id: str) -> bool:
        self.db.revoke_api_key(key_id)
        return True

    def list_keys(self, tenant_id: str) -> list[APIKey]:
        records = self.db.list_api_keys(tenant_id)
        return [
            APIKey(
                id=r.key_id,
                tenant_id=r.tenant_id,
                user_id=r.user_id,
                key_hash=r.key_hash,
                name=r.name,
                permissions=[Permission(p) for p in r.permissions],
                created_at=r.created_at,
                expires_at=r.expires_at,
                last_used=r.last_used
            )
            for r in records
        ]

    def create_user(
        self,
        tenant_id: str,
        name: str,
        email: str,
        role: Role = Role.VIEWER,
    ) -> User:
        user = User(tenant_id=tenant_id, name=name, email=email, role=role)
        record = UserRecord(
            user_id=user.id,
            tenant_id=user.tenant_id,
            name=user.name,
            email=user.email,
            role=str(user.role),
            created_at=user.created_at,
            last_login=user.last_login
        )
        self.db.save_user(record)
        return user

    def get_user(self, user_id: str) -> Optional[User]:
        record = self.db.get_user(user_id)
        if not record:
            return None
        return User(
            id=record.user_id,
            tenant_id=record.tenant_id,
            role=Role(record.role),
            name=record.name,
            email=record.email,
            created_at=record.created_at,
            last_login=record.last_login
        )


_global_store: Optional[AuthStore] = None


def get_auth_store() -> AuthStore:
    global _global_store
    if _global_store is None:
        _global_store = AuthStore()
    return _global_store


class AuthMiddleware:
    def __init__(self, store: Optional[AuthStore] = None):
        self.store = store or get_auth_store()

    def authenticate(self, api_key: Optional[str]) -> Optional[TenantContext]:
        if not api_key:
            return None

        key = self.store.validate_key(api_key)
        if not key:
            return None

        user = self.store.get_user(key.user_id)
        if not user:
            return None

        return TenantContext(tenant_id=key.tenant_id, user_id=key.user_id, role=user.role)
