from __future__ import annotations

from typing import Any, Iterable

from colorama import Fore, Style, init

# Windows terminal desteği için başlat
init(autoreset=True)


class TimelineEngine:
    """
    Simple timeline "brain":
    - Collects events from modules in a normalized shape
    - Sorts by the standardized timestamp field
    """

    def __init__(self):
        self.master_timeline: list[dict[str, Any]] = []

    def add_events(self, events: Iterable[dict[str, Any]], module_name: str):
        for event in events:
            # Her olay için ortak bir 'timestamp' anahtarı standardize edilir
            self.master_timeline.append(
                {
                    "time": event.get("timestamp") or event.get("created") or event.get("timestamp_start"),
                    "source": module_name,
                    "detail": event.get("description") or event.get("text") or event.get("id"),
                }
            )

    def generate_sorted_timeline(self):
        # Zaman damgasına göre sırala (geçersiz tarihleri sona atar)
        return sorted(self.master_timeline, key=lambda x: str(x["time"]))

    def display_terminal(self):
        print(f"\n{Fore.CYAN}{'='*85}")
        print(f"{Fore.CYAN}  MASTER TIMELINE - RECONSTRUCTED EVENTS")
        print(f"{Fore.CYAN}{'='*85}")
        print(f"{'TIMESTAMP':<20} | {'SOURCE':<20} | {'EVENT DETAIL'}")
        print("-" * 85)

        sorted_list = self.generate_sorted_timeline()

        for event in sorted_list:
            color = Fore.WHITE
            detail = str(event.get("detail"))

            # Kritiklik Seviyesine Göre Renklendirme
            if any(x in detail.upper() for x in ["DELETED", "CLEARED", "CRITICAL", "OVERRIDE"]):
                color = Fore.RED + Style.BRIGHT
            elif "AUDIO" in str(event.get("source", "")).upper():
                color = Fore.YELLOW
            elif "USB" in detail.upper():
                color = Fore.GREEN

            print(
                f"{Fore.BLUE}{str(event.get('time'))[:19]:<20}{Fore.RESET} | "
                f"{Fore.MAGENTA}{str(event.get('source', '')):<20}{Fore.RESET} | "
                f"{color}{detail}"
            )

        print(f"{Fore.CYAN}{'='*85}\n")

