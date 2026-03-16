from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

import winreg

from src.core.base_collector import CollectorContext, PluginCollector


class RegistryScanner(PluginCollector):
    """
    Live registry triage (Windows).

    - USB storage history: HKLM\\SYSTEM\\CurrentControlSet\\Enum\\USBSTOR
    - UserAssist presence: HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist

    Offline hive parsing is intentionally left as a future extension.
    """

    name = "registry_scanner"
    version = "0.1.0"
    description = "Scan critical Windows registry keys (USBSTOR, UserAssist) in live mode."

    supports_live = True
    supports_path = True

    # Analiz edilecek kritik anahtar yolları
    USB_PATH = r"SYSTEM\CurrentControlSet\Enum\USBSTOR"
    USER_ASSIST = r"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist"

    def collect(self):
        # Live modda winreg kullanacağı için path döndürmesine gerek yok
        return None

    def get_usb_devices(self) -> list[dict[str, Any]]:
        devices: list[dict[str, Any]] = []
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, self.USB_PATH) as key:
                subkeys, _, _ = winreg.QueryInfoKey(key)
                for i in range(subkeys):
                    device_name = winreg.EnumKey(key, i)
                    devices.append({"type": "USB_DEVICE", "id": device_name})
        except Exception as e:
            devices.append({"error": f"Could not access USBSTOR: {str(e)}"})
        return devices

    def get_userassist_summary(self) -> dict[str, Any]:
        """
        Minimal UserAssist visibility check (does not decode ROT13/counts yet).
        """
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, self.USER_ASSIST) as key:
                subkeys, _, _ = winreg.QueryInfoKey(key)
                # GUID subkeys under UserAssist
                guids: list[str] = []
                for i in range(min(subkeys, 20)):
                    guids.append(winreg.EnumKey(key, i))
                return {"present": True, "guid_subkeys_sample": guids, "guid_subkey_count": subkeys}
        except FileNotFoundError:
            return {"present": False}
        except Exception as e:
            return {"present": False, "error": str(e)}

    def parse(self):
        if getattr(self, "mode", None) == "live":
            usb = self.get_usb_devices()
            ua = self.get_userassist_summary()
            self.results = {
                "usb_devices": usb,
                "usb_devices_count": len([d for d in usb if isinstance(d, dict) and d.get("type") == "USB_DEVICE"]),
                "userassist": ua,
            }
        else:
            # Path modu için offline hive parsing kütüphanesi gerekecek
            self.results = {"info": "Offline hive parsing not implemented yet"}
        return self.results

    async def collect_live(self, ctx: CollectorContext) -> dict[str, Any]:
        return await asyncio.to_thread(self.parse)

    async def collect_path(self, ctx: CollectorContext, root: Path) -> dict[str, Any]:
        # Future: parse offline hives from root
        return await asyncio.to_thread(self.parse)


def get_collector() -> PluginCollector:
    return RegistryScanner()

