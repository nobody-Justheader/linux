"""
ShadowOS Kernel Module Test Fixtures
Provides sysfs interaction helpers for testing kernel modules.
"""

import os
import pytest
import subprocess
import time

SYSFS_BASE = "/sys/kernel/shadowos"


class ShadowModule:
    """Helper class for interacting with a ShadowOS kernel module via sysfs."""
    
    def __init__(self, name: str):
        self.name = name
        self.path = os.path.join(SYSFS_BASE, name)
    
    @property
    def available(self) -> bool:
        """Check if module sysfs directory exists."""
        return os.path.isdir(self.path)
    
    def read(self, attr: str) -> str:
        """Read a sysfs attribute."""
        try:
            with open(os.path.join(self.path, attr), 'r') as f:
                return f.read().strip()
        except (IOError, FileNotFoundError):
            return None
    
    def write(self, attr: str, value: str) -> bool:
        """Write to a sysfs attribute."""
        try:
            with open(os.path.join(self.path, attr), 'w') as f:
                f.write(value)
            return True
        except (IOError, PermissionError) as e:
            pytest.skip(f"Cannot write to {self.name}/{attr}: {e}")
            return False
    
    @property
    def enabled(self) -> bool:
        """Check if module is enabled."""
        val = self.read('enabled')
        return val == '1' if val else False
    
    @enabled.setter
    def enabled(self, value: bool):
        """Enable or disable module."""
        self.write('enabled', '1' if value else '0')
    
    def get_stats(self) -> dict:
        """Parse stats file into dict."""
        stats_str = self.read('stats')
        if not stats_str:
            return {}
        result = {}
        for line in stats_str.split('\n'):
            if ':' in line:
                key, val = line.split(':', 1)
                result[key.strip()] = val.strip()
        return result


@pytest.fixture
def shadow_av():
    """Fixture for shadow_av module."""
    mod = ShadowModule('av')
    if not mod.available:
        pytest.skip("shadow_av module not loaded")
    yield mod


@pytest.fixture
def shadow_cloak():
    """Fixture for shadow_cloak module."""
    mod = ShadowModule('cloak')
    if not mod.available:
        pytest.skip("shadow_cloak module not loaded")
    yield mod


@pytest.fixture
def shadow_detect():
    """Fixture for shadow_detect module."""
    mod = ShadowModule('detect')
    if not mod.available:
        pytest.skip("shadow_detect module not loaded")
    yield mod


@pytest.fixture
def shadow_frustrate():
    """Fixture for shadow_frustrate module."""
    mod = ShadowModule('frustrate')
    if not mod.available:
        pytest.skip("shadow_frustrate module not loaded")
    yield mod


@pytest.fixture
def shadow_phantom():
    """Fixture for shadow_phantom module."""
    mod = ShadowModule('phantom')
    if not mod.available:
        pytest.skip("shadow_phantom module not loaded")
    yield mod


@pytest.fixture
def shadow_decoy():
    """Fixture for shadow_decoy module."""
    mod = ShadowModule('decoy')
    if not mod.available:
        pytest.skip("shadow_decoy module not loaded")
    yield mod


@pytest.fixture
def shadow_deadman():
    """Fixture for shadow_deadman module."""
    mod = ShadowModule('deadman')
    if not mod.available:
        pytest.skip("shadow_deadman module not loaded")
    yield mod


@pytest.fixture
def shadow_timelock():
    """Fixture for shadow_timelock module."""
    mod = ShadowModule('timelock')
    if not mod.available:
        pytest.skip("shadow_timelock module not loaded")
    yield mod


@pytest.fixture
def shadow_shred():
    """Fixture for shadow_shred module."""
    mod = ShadowModule('shred')
    if not mod.available:
        pytest.skip("shadow_shred module not loaded")
    yield mod


def require_root():
    """Skip test if not running as root."""
    if os.geteuid() != 0:
        pytest.skip("Test requires root privileges")


def run_cmd(cmd: list, timeout: int = 5) -> tuple:
    """Run command and return (returncode, stdout, stderr)."""
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "Command timed out"
