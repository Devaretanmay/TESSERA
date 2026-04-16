from dataclasses import dataclass, field
from typing import Optional
from pathlib import Path
import json
import hashlib


@dataclass
class ProbePackage:
    name: str
    version: str
    description: str
    author: str
    category: str
    probes: list[dict]
    dependencies: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "author": self.author,
            "category": self.category,
            "probes": self.probes,
            "dependencies": self.dependencies,
            "tags": self.tags,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "ProbePackage":
        return cls(
            name=data["name"],
            version=data["version"],
            description=data["description"],
            author=data["author"],
            category=data["category"],
            probes=data["probes"],
            dependencies=data.get("dependencies", []),
            tags=data.get("tags", []),
        )


class ProbeRegistry:
    def __init__(self, registry_path: Optional[str] = None):
        self.registry_path = registry_path or "/tmp/tessera_registry"
        self._packages: dict[str, ProbePackage] = {}
        self._load_registry()

    def _load_registry(self) -> None:
        p = Path(self.registry_path)
        if p.exists():
            for f in p.glob("*.json"):
                try:
                    data = json.loads(f.read_text())
                    pkg = ProbePackage.from_dict(data)
                    self._packages[f"{pkg.name}:{pkg.version}"] = pkg
                except Exception:
                    pass

    def _ensure_registry_dir(self) -> None:
        Path(self.registry_path).mkdir(parents=True, exist_ok=True)

    def publish(self, package: ProbePackage) -> str:
        self._ensure_registry_dir()
        key = f"{package.name}:{package.version}"
        self._packages[key] = package

        filepath = Path(self.registry_path) / f"{package.name}_{package.version}.json"
        filepath.write_text(json.dumps(package.to_dict(), indent=2))

        return key

    def install(self, name: str, version: str = "latest") -> ProbePackage | None:
        key = f"{name}:{version}" if version != "latest" else None
        if not key:
            for k, pkg in self._packages.items():
                if pkg.name == name:
                    key = k
                    break

        return self._packages.get(key)

    def search(
        self,
        query: str | None = None,
        category: str | None = None,
        tags: list[str] | None = None,
    ) -> list[ProbePackage]:
        results = list(self._packages.values())

        if query:
            query_lower = query.lower()
            results = [
                p
                for p in results
                if query_lower in p.name.lower() or query_lower in p.description.lower()
            ]

        if category:
            results = [p for p in results if p.category == category]

        if tags:
            results = [p for p in results if any(t in p.tags for t in tags)]

        return results

    def list_all(self) -> list[dict]:
        return [
            {"name": p.name, "version": p.version, "category": p.category, "author": p.author}
            for p in self._packages.values()
        ]

    def get_probes(self, name: str, version: str) -> list[dict] | None:
        pkg = self.install(name, version)
        return pkg.probes if pkg else None


def create_probe_package(
    name: str,
    version: str,
    description: str,
    author: str,
    category: str,
    probes: list[dict],
    tags: list[str] | None = None,
) -> ProbePackage:
    return ProbePackage(
        name=name,
        version=version,
        description=description,
        author=author,
        category=category,
        probes=probes,
        tags=tags or [],
    )


def get_registry() -> ProbeRegistry:
    return ProbeRegistry()
