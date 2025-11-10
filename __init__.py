import asyncio
import logging
from datetime import timedelta

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import Platform
from homeassistant.core import HomeAssistant
from homeassistant.helpers.typing import ConfigType
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .const import DOMAIN, DEFAULT_SCAN_INTERVAL, REGISTERS
from .modbus_client import EasunModbusClient

_LOGGER = logging.getLogger(__name__)

PLATFORMS = [Platform.SENSOR, Platform.BUTTON]


async def async_setup(hass: HomeAssistant, config: ConfigType) -> bool:
    """Set up the EASUN SMX integration (YAML not supported)."""
    hass.data.setdefault(DOMAIN, {})
    return True


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up EASUN SMX from a config entry."""
    _LOGGER.info("Setting up EASUN SMX integration for %s", entry.data.get("host"))

    try:
        host = entry.data["host"]
        port = entry.data.get("port", 502)

        _LOGGER.info("Creating client for %s:%s", host, port)
        client = EasunModbusClient(host, port)

        async def async_update_data():
            """Fetch data from the inverter."""
            try:
                _LOGGER.debug("Fetching data from inverter")
                
                # Add timeout to prevent hanging
                data = await asyncio.wait_for(
                    hass.async_add_executor_job(client.read_all_registers, REGISTERS),
                    timeout=60.0
                )
                
                if not data:
                    _LOGGER.warning("No data received from inverter")
                    raise UpdateFailed("No data received from inverter")
                
                _LOGGER.debug("Received %d values", len(data))
                return data
                
            except asyncio.TimeoutError:
                _LOGGER.error("Timeout fetching data from inverter")
                await hass.async_add_executor_job(client.disconnect)
                raise UpdateFailed("Timeout communicating with inverter")
            except Exception as err:
                _LOGGER.error("Update failed: %s", err, exc_info=True)
                await hass.async_add_executor_job(client.disconnect)
                raise UpdateFailed(f"Error: {err}") from err

        coordinator = DataUpdateCoordinator(
            hass,
            _LOGGER,
            name=DOMAIN,
            update_method=async_update_data,
            update_interval=timedelta(seconds=DEFAULT_SCAN_INTERVAL),
        )

        _LOGGER.info("Performing first refresh (this may take up to 60 seconds)")
        
        # Add timeout for first refresh
        try:
            await asyncio.wait_for(
                coordinator.async_config_entry_first_refresh(),
                timeout=90.0
            )
        except asyncio.TimeoutError:
            _LOGGER.error("First refresh timed out after 90 seconds")
            await hass.async_add_executor_job(client.disconnect)
            raise ConfigEntryNotReady("Timeout during initial connection")

        hass.data.setdefault(DOMAIN, {})
        hass.data[DOMAIN][entry.entry_id] = {
            "coordinator": coordinator,
            "client": client,
        }

        _LOGGER.info("Forwarding setup to platforms: %s", PLATFORMS)
        await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)

        _LOGGER.info("EASUN SMX setup completed successfully")
        return True

    except Exception as err:
        _LOGGER.error("Setup failed: %s", err, exc_info=True)
        raise


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry."""
    _LOGGER.info("Unloading EASUN SMX integration")

    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)

    if unload_ok:
        client = hass.data[DOMAIN][entry.entry_id]["client"]
        await hass.async_add_executor_job(client.disconnect)
        hass.data[DOMAIN].pop(entry.entry_id)
        _LOGGER.info("EASUN SMX unloaded successfully")

    return unload_ok


class ConfigEntryNotReady(Exception):
    """Config entry not ready."""