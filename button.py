import logging

from homeassistant.components.button import ButtonEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN

_LOGGER = logging.getLogger(__name__)

BUTTONS = {
    "battery_equalization": {
        "name": "Start Battery Equalization",
        "icon": "mdi:battery-sync",
        "address": 0xDF0D,
        "value": 1,
    },
    "machine_reset": {
        "name": "Reset Machine",
        "icon": "mdi:restart",
        "address": 0xDF01,
        "value": 1,
    },
    "machine_shutdown": {
        "name": "Shutdown Machine",
        "icon": "mdi:power",
        "address": 0xDF00,
        "value": 0,
    },
    "machine_boot": {
        "name": "Boot Machine",
        "icon": "mdi:power",
        "address": 0xDF00,
        "value": 1,
    },
}


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up EASUN SMX buttons."""
    coordinator = hass.data[DOMAIN][entry.entry_id]["coordinator"]

    entities = []
    for key, config in BUTTONS.items():
        entities.append(EasunButton(coordinator, entry, key, config))

    _LOGGER.info("Created %d button entities", len(entities))
    async_add_entities(entities)


class EasunButton(CoordinatorEntity, ButtonEntity):
    """Representation of an EASUN SMX button."""

    def __init__(self, coordinator, entry, key, config):
        """Initialize the button."""
        super().__init__(coordinator)
        self._key = key
        self._config = config
        self._attr_name = f"EASUN SMX {config['name']}"
        self._attr_unique_id = f"{entry.entry_id}_{key}"
        self._attr_icon = config["icon"]

    async def async_press(self) -> None:
        """Handle the button press."""
        try:
            client = self.coordinator.client
            address = self._config["address"]
            value = self._config["value"]

            _LOGGER.info(
                "Button %s pressed: writing value %d to register 0x%04X",
                self._key,
                value,
                address,
            )

            success = await self.hass.async_add_executor_job(
                client.write_register, address, value
            )

            if success:
                _LOGGER.info("Button %s: command sent successfully", self._key)
                await self.coordinator.async_request_refresh()
            else:
                _LOGGER.error("Button %s: failed to send command", self._key)

        except Exception as err:
            _LOGGER.error("Button %s: error sending command: %s", self._key, err)
            
            if success:
                _LOGGER.info("Button %s: command sent successfully", self._key)
                await self.coordinator.async_request_refresh()
            else:
                _LOGGER.error("Button %s: failed to send command", self._key)
                
        except Exception as err:
            _LOGGER.error("Button %s: error sending command: %s", self._key, err)

    @property
    def device_info(self):
        """Return device information."""
        return {
            "identifiers": {(DOMAIN, self.coordinator.config_entry.entry_id)},
            "name": "EASUN ISOLAR SMX II",
            "manufacturer": "EASUN",
            "model": "ISOLAR SMX II",
        }
