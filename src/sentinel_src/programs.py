from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class ProgramPreset:
    name: str
    config: Path
    targets: Path
    output_dir: Path
    default_targets: tuple[str, ...]
    interval: str = "2h"
    note: str = ""


PROGRAMS: dict[str, ProgramPreset] = {
    "vala": ProgramPreset(
        name="vala",
        config=Path("examples/vala-visible-scope.toml"),
        targets=Path("examples/vala-targets.txt"),
        output_dir=Path("runs/vala"),
        default_targets=("https://www.51vala.com/", "https://vala.life/"),
        interval="2h",
        note=(
            "valaSRC: 09:00–21:00 自动低速单轮扫；21:00–09:00 才允许批量/循环。"
            "结果在 runs/vala/suspicious.md"
        ),
    ),
}


def resolve_targets_file(preset: ProgramPreset) -> Path | None:
    if preset.targets.exists():
        return preset.targets
    # examples/vala-targets.txt -> examples/vala-targets.example.txt
    example = preset.targets.parent / f"{preset.targets.stem}.example{preset.targets.suffix}"
    if example.exists():
        return example
    return None
