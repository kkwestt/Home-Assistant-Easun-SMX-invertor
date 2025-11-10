import logging
from typing import Any, Dict, Optional
import asyncio

import voluptuous as vol

from homeassistant import config_entries
from homeassistant.const import CONF_HOST, CONF_PORT
from homeassistant.core import HomeAssistant
from homeassistant.data_entry_flow import FlowResult

from .const import DOMAIN, DEFAULT_PORT
from .modbus_client import EasunModbusClient

_LOGGER = logging.getLogger(__name__)

STEP_USER_DATA_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_HOST): str,
        vol.Optional(CONF_PORT, default=DEFAULT_PORT): int,
    }
)


async def validate_input(hass: HomeAssistant, data: Dict[str, Any]) -> Dict[str, Any]:
    """Validate the user input allows us to connect."""
    _LOGGER.info("Validating connection to %s:%s", data[CONF_HOST], data[CONF_PORT])
    
    client = EasunModbusClient(data[CONF_HOST], data[CONF_PORT])
    
    try:
        _LOGGER.info("Attempting to connect with 45 second timeout...")
        # Use asyncio.wait_for to add timeout
        connected = await asyncio.wait_for(
            hass.async_add_executor_job(client.connect),
            timeout=45.0
        )
        
        if not connected:
            _LOGGER.error("Failed to connect to inverter")
            raise CannotConnect("Connection failed - check logs for details")
        
        _LOGGER.info("Connection successful, disconnecting...")
        await hass.async_add_executor_job(client.disconnect)
        
        return {"title": f"EASUN SMX {data[CONF_HOST]}"}
        
    except asyncio.TimeoutError:
        _LOGGER.error("Connection timeout after 45 seconds")
        await hass.async_add_executor_job(client.disconnect)
        raise CannotConnect("Connection timeout - inverter did not respond")
    except CannotConnect:
        await hass.async_add_executor_job(client.disconnect)
        raise
    except Exception as err:
        _LOGGER.error("Unexpected error during validation: %s", err, exc_info=True)
        await hass.async_add_executor_job(client.disconnect)
        raise CannotConnect(f"Validation error: {err}")


class EasunConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle a config flow for EASUN SMX."""

    VERSION = 1

    async def async_step_user(
        self, user_input: Optional[Dict[str, Any]] = None
    ) -> FlowResult:
        """Handle the initial step."""
        errors = {}

        if user_input is not None:
            try:
                _LOGGER.info("User input received: %s", user_input)
                info = await validate_input(self.hass, user_input)
                
                await self.async_set_unique_id(user_input[CONF_HOST])
                self._abort_if_unique_id_configured()
                
                _LOGGER.info("Creating config entry: %s", info["title"])
                return self.async_create_entry(title=info["title"], data=user_input)
                
            except CannotConnect as err:
                _LOGGER.error("Cannot connect: %s", err)
                errors["base"] = "cannot_connect"
            except Exception as err:
                _LOGGER.exception("Unexpected exception during config flow: %s", err)
                errors["base"] = "unknown"

        return self.async_show_form(
            step_id="user", data_schema=STEP_USER_DATA_SCHEMA, errors=errors
        )


class CannotConnect(Exception):
    """Error to indicate we cannot connect.""" 