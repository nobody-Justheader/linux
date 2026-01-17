# ShadowOS Control Center - Tab Modules
from .defense import DefenseTab
from .deception import DeceptionTab
from .network import NetworkTab
from .hardware import HardwareTab
from .storage import StorageTab
from .emergency import EmergencyTab
from .monitor import MonitorTab

__all__ = [
    'DefenseTab',
    'DeceptionTab',
    'NetworkTab',
    'HardwareTab',
    'StorageTab',
    'EmergencyTab',
    'MonitorTab',
]
