"""
arena.levels — Load and parse the 6 policy configuration levels.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict

from spanguard import config
from spanguard.policy import Policy


class LevelConfig(BaseModel):
    """Configuration definition for an Arena level."""

    model_config = ConfigDict(frozen=True)

    level: int
    name: str
    description: str
    enabled_layers: tuple[str, ...] = ()


def load_level_config(level: int, levels_dir: str | Path | None = None) -> LevelConfig:
    """Load configuration for a specific level from YAML."""
    if level < config.ARENA_LEVEL_MIN or level > config.ARENA_LEVEL_MAX:
        msg = f"{config.ARENA_MSG_INVALID_LEVEL}: {level}"
        raise ValueError(msg)

    base_dir = Path(levels_dir) if levels_dir is not None else Path(config.ARENA_LEVELS_DIR)
    filename = config.ARENA_LEVEL_FILENAME_TEMPLATE.format(level=level)
    path = base_dir / filename

    if not path.is_file():
        msg = f"Level file not found: {path}"
        raise FileNotFoundError(msg)

    content = path.read_text(encoding="utf-8")
    data: dict[str, Any] = yaml.safe_load(content)

    return LevelConfig(
        level=int(data[config.ARENA_RESP_LEVEL_KEY]),
        name=str(data[config.ARENA_RESP_NAME_KEY]),
        description=str(data[config.ARENA_RESP_DESCRIPTION_KEY]),
        enabled_layers=tuple(data.get(config.ARENA_RESP_ENABLED_LAYERS_KEY, ())),
    )


def load_all_levels(levels_dir: str | Path | None = None) -> list[LevelConfig]:
    """Load all 6 level configurations ordered from 1 to 6."""
    return [
        load_level_config(lvl, levels_dir=levels_dir)
        for lvl in range(config.ARENA_LEVEL_MIN, config.ARENA_LEVEL_MAX + 1)
    ]


def create_level_policy(level_config: LevelConfig, canary: str) -> Policy:
    """Instantiate a Spanguard Policy for the specified level and session canary."""
    return Policy(
        enabled_layers=level_config.enabled_layers,
        canary_secrets=(canary,),
        policy_id=f"arena_level_{level_config.level}",
    )
