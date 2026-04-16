import yaml
from pathlib import Path


class GarakProbeImporter:
    def __init__(self, garak_path: Path):
        self.garak_path = Path(garak_path)
        self.probes_dir = self.garak_path / "garak" / "probes"

    def import_probes(self) -> list[dict]:
        if not self.probes_dir.exists():
            return []

        imported = []
        for probe_file in self.probes_dir.glob("*.py"):
            if probe_file.name.startswith("_"):
                continue

            probe_data = self._parse_probe(probe_file)
            if probe_data:
                imported.append(probe_data)

        return imported

    def _parse_probe(self, probe_file: Path) -> dict | None:
        try:
            content = probe_file.read_text()

            name = probe_file.stem
            class_name = "".join(word.capitalize() for word in name.split("_"))

            return {
                "id": f"garak_{name}",
                "name": class_name,
                "source": "garak",
                "original_file": str(probe_file),
                "imported_at": "2026-04-14",
            }
        except Exception:
            return None

    def get_probe_count(self) -> int:
        return len(list(self.probes_dir.glob("*.py"))) if self.probes_dir.exists() else 0


def import_garak(garak_path: str) -> dict:
    importer = GarakProbeImporter(garak_path)
    probes = importer.import_probes()
    count = importer.get_probe_count()

    return {
        "total_found": count,
        "imported": len(probes),
        "probes": probes,
    }
