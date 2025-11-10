"""Select platform for EASUN SMX integration."""
from __future__ import annotations

import logging
from typing import Any

from homeassistant.components.select import SelectEntity
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
    BATTERY_TYPE_MAP,
)

_LOGGER = logging.getLogger(__name__)

# Define select entities with their option mappings
SELECT_ENTITIES = {
    "output_priority": OUTPUT_PRIORITY_MAP,
    "charger_source_priority": CHARGER_SOURCE_PRIORITY_MAP,
    "ac_input_voltage_range": AC_INPUT_VOLTAGE_RANGE_MAP,
    "battery_type": BATTERY_TYPE_MAP,
}


async def async_setup_entry(
    hass: HomeAssistant,
    config_entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up EASUN SMX select entities."""
    coordinator = hass.data[DOMAIN][config_entry.entry_id]["coordinator"]
    client = hass.data[DOMAIN][config_entry.entry_id]["client"]

    selects = []
    
    for key, options_map in SELECT_ENTITIES.items():
        if key in REGISTERS:
            config = REGISTERS[key]
            selects.append(EasunSelect(coordinator, client, key, config, options_map))

    async_add_entities(selects)


class EasunSelect(CoordinatorEntity, SelectEntity):
    """Representation of an EASUN SMX select entity."""

    def __init__(
        self,
        coordinator,
        client,
        select_key: str,
        select_config: dict,
        options_map: dict,
    ) -> None:
        """Initialize the select entity."""
        super().__init__(coordinator)
        self._client = client
        self._select_key = select_key
        self._select_config = select_config
        self._options_map = options_map
        self._reverse_map = {v: k for k, v in options_map.items()}
        
        self._attr_name = f"EASUN SMX {select_config['name']}"
        self._attr_unique_id = f"easun_smx_{select_key}"
        self._attr_options = list(options_map.values())

    @property
    def current_option(self) -> str | None:
        """Return the current option."""
        if self.coordinator.data is None:
            return None
        
        value = self.coordinator.data.get(self._select_key)
        
        if value is None:
            return None
        
        # Convert numeric value to option string
        return self._options_map.get(int(value), None)

    async def async_select_option(self, option: str) -> None:
        """Change the selected option."""
        try:
            # Convert option string to numeric value
            numeric_value = self._reverse_map.get(option)
            
            if numeric_value is None:
                _LOGGER.error(f"Invalid option {option} for {self._select_key}")
                return
            
            success = await self.hass.async_add_executor_job(
                self._client.write_register, self._select_config, numeric_value
            )
            
            if success:
                _LOGGER.info(f"Successfully set {self._select_key} to {option}")
                # Request coordinator update
                await self.coordinator.async_request_refresh()
            else:
                _LOGGER.error(f"Failed to set {self._select_key} to {option}")
        except Exception as err:
            _LOGGER.error(f"Error setting {self._select_key}: {err}")

    @property
    def available(self) -> bool:
        """Return if entity is available."""
        return self.coordinator.last_update_success and self.coordinator.data is not None

    @property
    def device_info(self):
        """Return device information."""
        return {
            "identifiers": {(DOMAIN, self.coordinator.config_entry.entry_id)},
            "name": "EASUN ISOLAR SMX II",
            "manufacturer": "EASUN",
            "model": "ISOLAR SMX II",
        }