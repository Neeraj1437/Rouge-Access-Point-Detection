import datetime
import os
import platform
import re
import subprocess
import sys
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

LOG_FILE = "wifi_monitor.log"
EVENT_LOG_FILE = "wifi_monitor_events.log"
RAW_SCAN_FILE = "wifi_monitor_raw_scan.log"
SCAN_INTERVAL_SECONDS = 10
SIGNAL_HISTORY_WINDOW = 6
TRANSIENT_SECONDS = 30


@dataclass
class NetworkObservation:
    ssid: str
    bssid: str
    signal: Optional[int]
    channel: Optional[int]
    security: str
    timestamp: datetime.datetime


@dataclass
class NetworkProfile:
    bssid: str
    ssid_history: deque = field(default_factory=lambda: deque(maxlen=10))
    security_history: deque = field(default_factory=lambda: deque(maxlen=10))
    channel_history: deque = field(default_factory=lambda: deque(maxlen=10))
    signal_history: deque = field(default_factory=lambda: deque(maxlen=SIGNAL_HISTORY_WINDOW))
    timestamps: deque = field(default_factory=lambda: deque(maxlen=SIGNAL_HISTORY_WINDOW))
    first_seen: Optional[datetime.datetime] = None
    last_seen: Optional[datetime.datetime] = None
    observed_count: int = 0
    seen_recently: bool = False
    flags: Set[str] = field(default_factory=set)
    reasons: List[str] = field(default_factory=list)
    risk_score: int = 0
    classification: str = "unknown"

    def update(self, observation: NetworkObservation):
        if not self.first_seen:
            self.first_seen = observation.timestamp
        self.last_seen = observation.timestamp
        self.observed_count += 1
        self.seen_recently = True

        self._append_unique(self.ssid_history, observation.ssid)
        self._append_unique(self.security_history, observation.security)
        self._append_unique(self.channel_history, observation.channel)
        if observation.signal is not None:
            self.signal_history.append(observation.signal)
            self.timestamps.append(observation.timestamp)

    @staticmethod
    def _append_unique(history: deque, value):
        if value is None:
            return
        if not history or history[-1] != value:
            history.append(value)

    @property
    def current_ssid(self):
        return self.ssid_history[-1] if self.ssid_history else "<unknown>"

    @property
    def current_security(self):
        return self.security_history[-1] if self.security_history else "<unknown>"

    @property
    def current_channel(self):
        return self.channel_history[-1] if self.channel_history else None

    @property
    def average_signal(self) -> Optional[float]:
        if not self.signal_history:
            return None
        return sum(self.signal_history) / len(self.signal_history)

    def signal_variation(self) -> Optional[float]:
        if len(self.signal_history) < 2:
            return None
        avg = self.average_signal
        variance = sum((x - avg) ** 2 for x in self.signal_history) / len(self.signal_history)
        return variance ** 0.5

    def age_seconds(self) -> Optional[float]:
        if not self.last_seen:
            return None
        return (datetime.datetime.now() - self.last_seen).total_seconds()

    def mark_not_seen(self):
        self.seen_recently = False


class WifiScanner:
    def scan(self) -> List[NetworkObservation]:
        system = platform.system()
        if system == "Windows":
            return self._scan_windows()
        if system == "Linux":
            return self._scan_linux()
        raise RuntimeError(f"Unsupported platform: {system}")

    def _scan_windows(self) -> List[NetworkObservation]:
        try:
            output = subprocess.check_output(
                ["netsh", "wlan", "show", "networks", "mode=bssid"],
                stderr=subprocess.DEVNULL,
                text=True,
                encoding="utf-8",
                errors="ignore",
            )
        except subprocess.CalledProcessError as exc:
            raise RuntimeError("Failed to run netsh WLAN scan") from exc
        self._dump_raw_scan_output(output)
        return self._parse_windows_output(output)

    def _dump_raw_scan_output(self, output: str):
        timestamp = datetime.datetime.now().isoformat()
        with open(RAW_SCAN_FILE, "a", encoding="utf-8") as raw_file:
            raw_file.write(f"--- {timestamp} ---\n")
            raw_file.write(output)
            raw_file.write("\n\n")

    def _parse_windows_output(self, output: str) -> List[NetworkObservation]:
        networks: List[NetworkObservation] = []
        ssid = None
        security = "Unknown"
        channel = None
        bssid = None
        signal = None
        timestamp = datetime.datetime.now()

        def commit_current():
            nonlocal bssid, signal, channel, ssid, security
            if ssid and bssid:
                networks.append(
                    NetworkObservation(
                        ssid=ssid,
                        bssid=bssid,
                        signal=signal,
                        channel=channel,
                        security=security,
                        timestamp=timestamp,
                    )
                )
            bssid = None
            signal = None
            channel = None

        for line in output.splitlines():
            stripped = line.strip()
            ssid_match = re.match(r"^SSID\s+\d+\s*:\s*(.*)$", stripped)
            bssid_match = re.match(r"^BSSID\s+\d+\s*:\s*(.*)$", stripped)
            channel_match = re.match(r"^Channel\s*:\s*(\d+)\s*$", stripped)
            signal_match = re.match(r"^Signal\s*:\s*(\d+)%\s*$", stripped)

            if ssid_match:
                commit_current()
                ssid = ssid_match.group(1).strip()
                security = "Unknown"
                channel = None
            elif stripped.startswith("Authentication") and ":" in stripped:
                security = stripped.split(":", 1)[1].strip()
            elif stripped.startswith("Encryption") and security == "Unknown" and ":" in stripped:
                security = stripped.split(":", 1)[1].strip()
            elif bssid_match:
                commit_current()
                bssid = bssid_match.group(1).strip()
            elif signal_match:
                signal = self._parse_int(signal_match.group(1))
            elif channel_match:
                channel = self._parse_int(channel_match.group(1))

        commit_current()
        return networks

    def _scan_linux(self) -> List[NetworkObservation]:
        try:
            output = subprocess.check_output(
                ["nmcli", "-f", "SSID,BSSID,SIGNAL,CHAN,SECURITY", "device", "wifi", "list"],
                stderr=subprocess.DEVNULL,
                text=True,
                encoding="utf-8",
                errors="ignore",
            )
        except subprocess.CalledProcessError as exc:
            raise RuntimeError("Failed to run nmcli wifi scan") from exc
        self._dump_raw_scan_output(output)
        return self._parse_linux_output(output)

    def _parse_linux_output(self, output: str) -> List[NetworkObservation]:
        networks: List[NetworkObservation] = []
        lines = output.splitlines()
        if not lines:
            return networks
        header, *rows = lines
        for row in rows:
            if not row.strip():
                continue
            parts = [part.strip() for part in re.split(r"\s{2,}", row) if part.strip()]
            if len(parts) < 5:
                continue
            ssid, bssid, signal, chan, security = parts[:5]
            networks.append(
                NetworkObservation(
                    ssid=ssid or "<hidden>",
                    bssid=bssid,
                    signal=self._parse_int(signal),
                    channel=self._parse_int(chan),
                    security=security or "Open",
                    timestamp=datetime.datetime.now(),
                )
            )
        return networks

    @staticmethod
    def _parse_int(value: str) -> Optional[int]:
        try:
            return int(value)
        except (TypeError, ValueError):
            return None


class NetworkMonitor:
    def __init__(self, scanner: WifiScanner):
        self.scanner = scanner
        self.networks: Dict[str, NetworkProfile] = {}
        self.history_by_ssid: Dict[str, Set[str]] = defaultdict(set)
        self.lock = threading.Lock()
        self.event_log_file = EVENT_LOG_FILE
        self.last_scan_count = 0
        self.last_scan_time: Optional[datetime.datetime] = None
        self.last_visible_bssids_by_ssid: Dict[str, Set[str]] = defaultdict(set)
        self._write_log_header()

    def _write_log_header(self):
        if not os.path.exists(LOG_FILE):
            with open(LOG_FILE, "w", encoding="utf-8") as log_file:
                log_file.write("timestamp,event,details\n")
        if not os.path.exists(self.event_log_file):
            with open(self.event_log_file, "w", encoding="utf-8") as event_file:
                event_file.write("timestamp,bssid,ssid,event,details\n")

    def _update_last_visible(self, current_visible_by_ssid: Dict[str, Set[str]]):
        self.last_visible_bssids_by_ssid = current_visible_by_ssid

    def log(self, event: str, details: str = ""):
        timestamp = datetime.datetime.now().isoformat()
        entry = f'{timestamp},{event},{details}\n'
        with open(LOG_FILE, "a", encoding="utf-8") as log_file:
            log_file.write(entry)

    def log_event(self, bssid: str, ssid: str, event: str, details: str = ""):
        timestamp = datetime.datetime.now().isoformat()
        entry = f'{timestamp},{bssid},{ssid},{event},{details}\n'
        with open(self.event_log_file, "a", encoding="utf-8") as event_file:
            event_file.write(entry)

    def run_scan_cycle(self):
        try:
            observations = self.scanner.scan()
        except Exception as exc:
            self.log("scan_error", str(exc))
            return

        with self.lock:
            now = datetime.datetime.now()
            seen_bssids = set()
            self.last_scan_count = len(observations)
            self.last_scan_time = now
            for obs in observations:
                seen_bssids.add(obs.bssid)
                profile = self.networks.get(obs.bssid)
                if not profile:
                    profile = NetworkProfile(bssid=obs.bssid)
                    self.networks[obs.bssid] = profile
                    self.log_event(obs.bssid, obs.ssid, "first_seen", "New network observed")
                profile.update(obs)
                self.history_by_ssid[obs.ssid].add(obs.bssid)

            if self.last_scan_count == 0:
                self.log_event("scan", "no_results", "No networks detected in this scan")

            for bssid, profile in self.networks.items():
                if bssid not in seen_bssids:
                    age = profile.age_seconds()
                    if profile.seen_recently and age is not None and age > TRANSIENT_SECONDS:
                        profile.mark_not_seen()
                        self.log_event(bssid, profile.current_ssid, "disappeared", "Network no longer visible")

            current_visible_by_ssid: Dict[str, Set[str]] = defaultdict(set)
            for obs in observations:
                current_visible_by_ssid[obs.ssid].add(obs.bssid)

            self._evaluate_profiles(seen_bssids)
            self._update_last_visible(current_visible_by_ssid)

    def _evaluate_profiles(self, visible_bssids: Set[str]):
        ssid_groups = defaultdict(list)
        for bssid, profile in self.networks.items():
            if bssid in visible_bssids:
                ssid_groups[profile.current_ssid].append(profile)

        for bssid, profile in self.networks.items():
            profile.flags.clear()
            profile.reasons.clear()
            profile.risk_score = 0
            self._score_duplicate_ssid(profile, ssid_groups, visible_bssids)
            self._score_parameter_inconsistency(profile, visible_bssids)
            self._score_signal_anomaly(profile)
            self._score_temporal_anomaly(profile, visible_bssids)
            self._assign_classification(profile)

    def _score_duplicate_ssid(
        self,
        profile: NetworkProfile,
        ssid_groups: Dict[str, List[NetworkProfile]],
        visible_bssids: Set[str],
    ):
        group = ssid_groups.get(profile.current_ssid, [])
        if len(group) <= 1:
            return

        visible_group = [p for p in group if p.bssid in visible_bssids]
        if len(visible_group) <= 1:
            return

        security_values = {p.current_security for p in visible_group if p.current_security and p.current_security != "<unknown>"}
        stable_members = [p for p in visible_group if p.observed_count >= 2]

        if len(security_values) == 1 and len(stable_members) >= 2:
            profile.flags.add("safe_same_ssid_multi_ap")
            self.log_event(
                profile.bssid,
                profile.current_ssid,
                "safe_same_ssid_multi_ap",
                "Same SSID on multiple currently visible stable APs with consistent security; likely legitimate campus/enterprise deployment",
            )
            return

        if len(security_values) > 1:
            profile.flags.add("duplicate_ssid_mixed_security")
            profile.risk_score += 25
            self.log_event(
                profile.bssid,
                profile.current_ssid,
                "duplicate_ssid_mixed_security",
                "Same SSID observed on multiple currently visible BSSIDs with inconsistent security",
            )
            return

        profile.flags.add("duplicate_ssid")
        profile.risk_score += 20
        profile.reasons.append("Same SSID seen on multiple currently visible BSSIDs")
        self.log_event(profile.bssid, profile.current_ssid, "duplicate_ssid", "Same SSID observed on multiple currently visible BSSIDs")

    def _score_parameter_inconsistency(self, profile: NetworkProfile, visible_bssids: Set[str]):
        if profile.bssid not in visible_bssids:
            return
        if len(set(profile.security_history)) > 1:
            profile.flags.add("security_inconsistency")
            profile.risk_score += 15
            profile.reasons.append("Security configuration has changed over time")
            self.log_event(profile.bssid, profile.current_ssid, "security_inconsistency", f"Security types changed: {list(set(profile.security_history))}")
        if len({ch for ch in profile.channel_history if ch is not None}) > 1:
            profile.flags.add("channel_inconsistency")
            profile.risk_score += 10
            profile.reasons.append("Channel usage has varied over time")
            self.log_event(profile.bssid, profile.current_ssid, "channel_inconsistency", f"Channels observed: {list({ch for ch in profile.channel_history if ch is not None})}")

    def _score_signal_anomaly(self, profile: NetworkProfile):
        if len(profile.signal_history) < 3:
            return
        avg = profile.average_signal
        variation = profile.signal_variation()
        if avg is None or variation is None:
            return
        recent = profile.signal_history[-1]
        if abs(recent - avg) > max(8, variation * 1.5):
            profile.flags.add("signal_anomaly")
            profile.risk_score += 10
            self.log_event(profile.bssid, profile.current_ssid, "signal_anomaly", f"Recent RSSI {recent} deviates from avg {avg:.1f}")

    def _score_temporal_anomaly(self, profile: NetworkProfile, visible_bssids: Set[str]):
        if profile.bssid not in visible_bssids:
            return
        current_ssid = profile.current_ssid
        previous_visible = self.last_visible_bssids_by_ssid.get(current_ssid, set())
        if previous_visible and profile.bssid not in previous_visible:
            if previous_visible.isdisjoint({profile.bssid}):
                profile.flags.add("temporal_anomaly")
                profile.risk_score += 20
                profile.reasons.append("SSID has been replaced by a different BSSID since the last scan")
                self.log_event(
                    profile.bssid,
                    profile.current_ssid,
                    "temporal_anomaly",
                    f"Previous visible BSSIDs={sorted(previous_visible)}, current BSSID={profile.bssid}",
                )

    def _assign_classification(self, profile: NetworkProfile):
        if profile.risk_score >= 50:
            profile.classification = "high"
        elif profile.risk_score >= 20:
            profile.classification = "suspicious"
        else:
            profile.classification = "trusted"

    def get_profiles(self) -> List[NetworkProfile]:
        with self.lock:
            return sorted(self.networks.values(), key=lambda p: (p.classification, p.current_ssid, p.bssid), reverse=True)

    def get_current_ssids(self) -> List[str]:
        with self.lock:
            return sorted({p.current_ssid for p in self.networks.values()})


def clear_console():
    os.system("cls" if os.name == "nt" else "clear")


def format_signal(value: Optional[int]) -> str:
    return f"{value}%" if value is not None else "N/A"


def print_status(monitor: NetworkMonitor):
    clear_console()
    profiles = monitor.get_profiles()
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"Wi-Fi Rogue Monitor - {now}")
    print("Scan interval:", SCAN_INTERVAL_SECONDS, "seconds")
    print("Visible APs this scan:", monitor.last_scan_count)
    print("Tracked BSSIDs:", len(profiles), "| Unique SSIDs:", len(monitor.get_current_ssids()))
    print("Last scan:", monitor.last_scan_time.strftime("%Y-%m-%d %H:%M:%S") if monitor.last_scan_time else "never")
    print("Logs:", LOG_FILE, EVENT_LOG_FILE, RAW_SCAN_FILE)
    print("Note: same SSID can appear on multiple APs; suspicious entries are flagged below.")
    print("\n{:<24} {:<20} {:<7} {:<7} {:<12} {:<6} {:<6} {:<12} {}".format(
        "BSSID", "SSID", "Signal", "Chan", "Security", "Seen", "Score", "Class", "Flags"
    ))
    print("-" * 120)

    for profile in profiles:
        flags = ",".join(sorted(profile.flags)) if profile.flags else "-"
        print(
            "{:<24} {:<20} {:<7} {:<7} {:<12} {:<6} {:<6} {:<12} {}".format(
                profile.bssid,
                profile.current_ssid[:20],
                format_signal(profile.signal_history[-1] if profile.signal_history else None),
                profile.current_channel or "N/A",
                profile.current_security[:12],
                f"{profile.observed_count}x",
                profile.risk_score,
                profile.classification,
                flags,
            )
        )
        if profile.reasons:
            print(f"  Reasons: {', '.join(profile.reasons[:2])}")

    suspicious_profiles = [p for p in profiles if p.classification != "trusted"]
    if suspicious_profiles:
        print("\nTop flagged profiles:")
        print("-" * 80)
        for profile in suspicious_profiles[:5]:
            print(f"BSSID: {profile.bssid} | SSID: {profile.current_ssid} | Class: {profile.classification} | Score: {profile.risk_score}")
            print(f"  Flags: {', '.join(sorted(profile.flags)) if profile.flags else 'none'}")
            if profile.reasons:
                print(f"  Reasons: {', '.join(profile.reasons[:2])}")
            print("-" * 80)


def run_monitor(simulate: bool = False):
    scanner = WifiScanner()
    monitor = NetworkMonitor(scanner)
    if simulate:
        print("Simulation mode enabled: using synthetic Wi-Fi observations.")

    try:
        while True:
            if simulate:
                observations = build_simulated_observations()
                visible_bssids = set()
                for obs in observations:
                    visible_bssids.add(obs.bssid)
                    profile = monitor.networks.get(obs.bssid)
                    if not profile:
                        profile = NetworkProfile(bssid=obs.bssid)
                        monitor.networks[obs.bssid] = profile
                    profile.update(obs)
                    monitor.history_by_ssid[obs.ssid].add(obs.bssid)
                monitor._evaluate_profiles(visible_bssids)
            else:
                monitor.run_scan_cycle()
            print_status(monitor)
            time.sleep(SCAN_INTERVAL_SECONDS)
    except KeyboardInterrupt:
        print("\nStopping monitor.")


def build_simulated_observations() -> List[NetworkObservation]:
    timestamp = datetime.datetime.now()
    simulated = [
        NetworkObservation("CoffeeShop", "00:11:22:33:44:55", 72, 6, "WPA2-Personal", timestamp),
        NetworkObservation("AirportFree", "aa:bb:cc:dd:ee:ff", 48, 11, "Open", timestamp),
        NetworkObservation("CoffeeShop", "00:11:22:33:44:66", 68, 6, "WPA2-Personal", timestamp),
        NetworkObservation("OfficeNet", "12:34:56:78:9a:bc", 81, 36, "WPA3-Personal", timestamp),
    ]
    if int(timestamp.second / SCAN_INTERVAL_SECONDS) % 2 == 0:
        simulated.append(NetworkObservation("OfficeNet", "12:34:56:78:9a:bd", 23, 36, "WPA2-Personal", timestamp))
    return simulated


def parse_args() -> bool:
    return "--simulate" in sys.argv or "-s" in sys.argv


if __name__ == "__main__":
    simulate_mode = parse_args()
    if simulate_mode:
        print("Starting Wi-Fi monitoring system in simulated mode. Use real scan by omitting --simulate.")
    else:
        print("Starting Wi-Fi monitoring system. Real Wi-Fi scan will be attempted.")
    run_monitor(simulate=simulate_mode)
