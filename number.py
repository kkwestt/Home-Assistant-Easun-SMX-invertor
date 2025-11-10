"""Number platform for EASUN SMX integration."""
from __future__ import annotations

import logging
from typing import Any

from homeassistant.components.number import NumberEntity, NumberMode
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import (
    UnitOfElectricCurrent,
    UnitOfElectricPotential,
    UnitOfFrequency,
)
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN, REGISTERS

_LOGGER = logging.getLogger(__name__)

# Define which holding registers should be exposed as number entities
ADJUSTABLE_REGISTERS = [
    "max_charger_current",
    "max_ac_charger_current",
    "max_pv_charger_current",
    "battery_boost_charge_voltage",
    "battery_floating_charge_voltage",
    "battery_over_discharge_voltage",
    "battery_under_voltage_alarm",
    "battery_discharge_limit_voltage",
    "battery_undervoltage_recovery",
    "battery_charge_recovery",
    "output_voltage_set",
]


async def async_setup_entry(
    hass: HomeAssistant,
    config_entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up EASUN SMX number entities."""
    coordinator = hass.data[DOMAIN][config_entry.entry_id]["coordinator"]
    client = hass.data[DOMAIN][config_entry.entry_id]["client"]

    numbers = []
    
    for key in ADJUSTABLE_REGISTERS:
        if key in REGISTERS:
            config = REGISTERS[key]
            numbers.append(EasunNumber(coordinator, client, key, config))

    async_add_entities(numbers)


class EasunNumber(CoordinatorEntity, NumberEntity):
    """Representation of an EASUN SMX number entity."""

    def __init__(self, coordinator, client, number_key: str, number_config: dict) -> None:
        """Initialize the number entity."""
        super().__init__(coordinator)
        self._client = client
        self._number_key = number_key
        self._number_config = number_config
        self._attr_name = f"EASUN SMX {number_config['name']}"
        self._attr_unique_id = f"easun_smx_{number_key}"
        self._attr_mode = NumberMode.BOX

        # Set unit of measurement
        unit_map = {
            "V": UnitOfElectricPotential.VOLT,
            "A": UnitOfElectricCurrent.AMPERE,
            "Hz": UnitOfFrequency.HERTZ,
        }
        
        unit = number_config.get("unit", "")
        self._attr_native_unit_of_measurement = unit_map.get(unit, unit)

        # Set min/max values based on parameter type
        scale = number_config.get("scale", 1.0)
        
        if "current" in number_key:
            self._attr_native_min_value = 0
            self._attr_native_max_value = 100
            self._attr_native_step = 0.1 if scale == 0.1 else 1
        elif "voltage" in number_key:
            self._attr_native_min_value = 20
            self._attr_native_max_value = 60
            self._attr_native_step = 0.1 if scale == 0.1 else 1
        elif "output_voltage" in number_key:
            self._attr_native_min_value = 200
            self._attr_native_max_value = 240
            self._attr_native_step = 0.1 if scale == 0.1 else 1
        else:
            self._attr_native_min_value = 0
            self._attr_native_max_value = 100
            self._attr_native_step = 1

    @property
    def native_value(self) -> float | None:
        """Return the current value."""
        if self.coordinator.data is None:
            return None
        
        value = self.coordinator.data.get(self._number_key)
        
        if value is None:
            return None
        
        # Round to appropriate precision
        if self._attr_native_step < 1:
            return round(value, 1)
        return round(value, 0)

    async def async_set_native_value(self, value: float) -> None:
        """Set new value."""
        try:
            success = await self.hass.async_add_executor_job(
                self._client.write_register, self._number_config, value
            )
            
            if success:
                _LOGGER.info(f"Successfully set {self._number_key} to {value}")
                # Request coordinator update
                await self.coordinator.async_request_refresh()
            else:
                _LOGGER.error(f"Failed to set {self._number_key} to {value}")
        except Exception as err:
            _LOGGER.error(f"Error setting {self._number_key}: {err}")

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