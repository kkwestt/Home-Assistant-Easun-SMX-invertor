"""Switch platform for EASUN SMX integration."""
from __future__ import annotations

import logging
from typing import Any

from homeassistant.components.switch import SwitchEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import (
    DOMAIN,
    REGISTERS,
    OUTPUT_PRIORITY_MAP,
    CHARGER_SOURCE_PRIORITY_MAP,
    AC_INPUT_VOLTAGE_RANGE_MAP,
)

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant,
    config_entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up EASUN SMX switches."""
    coordinator = hass.data[DOMAIN][config_entry.entry_id]["coordinator"]
    client = hass.data[DOMAIN][config_entry.entry_id]["client"]

    # No switches for now - configuration changes should be done carefully
    # and might be better suited for number/select entities
    # This file is kept for future expansion
    pass