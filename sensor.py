import logging

from homeassistant.components.sensor import (
    SensorDeviceClass,
    SensorEntity,
    SensorStateClass,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import (
    PERCENTAGE,
    UnitOfElectricCurrent,
    UnitOfElectricPotential,
    UnitOfEnergy,
    UnitOfFrequency,
    UnitOfPower,
    UnitOfTemperature,
)
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN, REGISTERS, OUTPUT_PRIORITY_MAP, CHARGER_SOURCE_PRIORITY_MAP

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up EASUN SMX sensors."""
    coordinator = hass.data[DOMAIN][entry.entry_id]["coordinator"]

    entities = []
    for key, config in REGISTERS.items():
        if config["type"] == "input":  # Only create sensors for input registers
            entities.append(EasunSensor(coordinator, entry, key, config))

    _LOGGER.info("Created %d sensor entities", len(entities))
    async_add_entities(entities)


class EasunSensor(CoordinatorEntity, SensorEntity):
    """Representation of an EASUN SMX sensor."""

    def __init__(self, coordinator, entry, key, config):
        """Initialize the sensor."""
        super().__init__(coordinator)
        self._key = key
        self._config = config
        self._attr_name = f"EASUN {config['name']}"
        self._attr_unique_id = f"{entry.entry_id}_{key}"

        # Set unit of measurement
        unit = config.get("unit", "")
        if unit == "V":
            self._attr_native_unit_of_measurement = UnitOfElectricPotential.VOLT
            self._attr_device_class = SensorDeviceClass.VOLTAGE
        elif unit == "A":
            self._attr_native_unit_of_measurement = UnitOfElectricCurrent.AMPERE
            self._attr_device_class = SensorDeviceClass.CURRENT
        elif unit == "W":
            self._attr_native_unit_of_measurement = UnitOfPower.WATT
            self._attr_device_class = SensorDeviceClass.POWER
        elif unit == "VA":
            self._attr_native_unit_of_measurement = "VA"
            self._attr_device_class = SensorDeviceClass.APPARENT_POWER
        elif unit == "Wh":
            self._attr_native_unit_of_measurement = UnitOfEnergy.WATT_HOUR
            self._attr_device_class = SensorDeviceClass.ENERGY
        elif unit == "kWh":
            self._attr_native_unit_of_measurement = UnitOfEnergy.KILO_WATT_HOUR
            self._attr_device_class = SensorDeviceClass.ENERGY
        elif unit == "Hz":
            self._attr_native_unit_of_measurement = UnitOfFrequency.HERTZ
            self._attr_device_class = SensorDeviceClass.FREQUENCY
        elif unit == "%":
            self._attr_native_unit_of_measurement = PERCENTAGE
            if "battery" in key.lower():
                self._attr_device_class = SensorDeviceClass.BATTERY
        elif unit == "°C":
            self._attr_native_unit_of_measurement = UnitOfTemperature.CELSIUS
            self._attr_device_class = SensorDeviceClass.TEMPERATURE
        else:
            self._attr_native_unit_of_measurement = unit

        # Set state class for numeric values
        if unit and unit not in ["", "status"]:
            if "energy" in key.lower() or "kwh" in key.lower():
                self._attr_state_class = SensorStateClass.TOTAL_INCREASING
            else:
                self._attr_state_class = SensorStateClass.MEASUREMENT

        if key == "battery_voltage":
            self._attr_suggested_display_precision = 2

    @property
    def native_value(self):
        """Return the state of the sensor."""
        if self.coordinator.data is None:
            return None

        value = self.coordinator.data.get(self._key)

        if value is None:
            return None

        # Map status values to readable strings
        if self._key == "output_priority":
            return OUTPUT_PRIORITY_MAP.get(int(value), f"Unknown ({value})")
        elif self._key == "charger_source_priority":
            return CHARGER_SOURCE_PRIORITY_MAP.get(int(value), f"Unknown ({value})")

        return value

    @property
    def available(self) -> bool:
        """Return if entity is available."""
        return self.coordinator.last_update_success

    @property
    def device_info(self):
        """Return device information."""
        return {
            "identifiers": {(DOMAIN, self.coordinator.config_entry.entry_id)},
            "name": "EASUN ISOLAR SMX II",
            "manufacturer": "EASUN",
            "model": "ISOLAR SMX II",
        } 