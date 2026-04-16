from typing import Protocol, Any, Callable
from dataclasses import dataclass
from enum import Enum


class HookPoint(str, Enum):
    BEFORE_SCAN = "before_scan"
    AFTER_SCAN = "after_scan"
    BEFORE_PROBE = "before_probe"
    AFTER_PROBE = "after_probe"
    ON_FINDING = "on_finding"
    ON_DRIFT = "on_drift"


@dataclass
class HookResult:
    success: bool
    data: Any = None
    error: str | None = None


class Plugin(Protocol):
    name: str
    version: str
    hooks: dict[HookPoint, Callable]

    def initialize(self, config: dict) -> None: ...
    def cleanup(self) -> None: ...


class PluginRegistry:
    def __init__(self):
        self._plugins: dict[str, Plugin] = {}
        self._hooks: dict[HookPoint, list[tuple[str, Callable]]] = {hp: [] for hp in HookPoint}

    def register(self, plugin: Plugin, config: dict | None = None) -> bool:
        try:
            if config:
                plugin.initialize(config)
            self._plugins[plugin.name] = plugin

            for hook_point, handler in plugin.hooks.items():
                self._hooks[hook_point].append((plugin.name, handler))

            return True
        except Exception:
            return False

    def unregister(self, name: str) -> bool:
        if name not in self._plugins:
            return False

        plugin = self._plugins.pop(name)
        plugin.cleanup()

        for hook_point in self._hooks:
            self._hooks[hook_point] = [(n, h) for n, h in self._hooks[hook_point] if n != name]
        return True

    def list(self) -> list[dict]:
        return [{"name": p.name, "version": p.version} for p in self._plugins.values()]

    async def execute_hook(self, hook_point: HookPoint, **kwargs) -> list[HookResult]:
        results = []
        for name, handler in self._hooks.get(hook_point, []):
            try:
                result = await handler(**kwargs)
                results.append(HookResult(success=True, data=result))
            except Exception as e:
                results.append(HookResult(success=False, error=str(e)))
        return results

    def get(self, name: str) -> Plugin | None:
        return self._plugins.get(name)


_global_registry: PluginRegistry | None = None


def get_plugin_registry() -> PluginRegistry:
    global _global_registry
    if _global_registry is None:
        _global_registry = PluginRegistry()
    return _global_registry


class PluginLoader:
    @staticmethod
    def from_python_module(module_path: str) -> Plugin | None:
        import importlib.util

        spec = importlib.util.spec_from_file_location("plugin", module_path)
        if spec and spec.loader:
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            if hasattr(module, "plugin"):
                return module.plugin
        return None


def create_example_plugin() -> type:
    class ExamplePlugin:
        name = "example"
        version = "1.0.0"
        hooks = {}

        def __init__(self):
            self.hooks = {
                HookPoint.AFTER_SCAN: self._on_after_scan,
            }

        def initialize(self, config: dict) -> None:
            pass

        def cleanup(self) -> None:
            pass

        async def _on_after_scan(self, scan_result: dict) -> dict:
            return {"plugin": "example", "processed": True}

    return ExamplePlugin
