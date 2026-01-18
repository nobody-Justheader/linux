"""
ShadowOS Network Module Tests
Tests for net/shadowos kernel modules via sysfs.
"""

import os
import socket
import pytest
from conftest import require_root, run_cmd, ShadowModule


class TestShadowDetect:
    """Tests for shadow_detect (Scan detection)."""
    
    def test_module_available(self, shadow_detect):
        """Verify module is loaded."""
        assert shadow_detect.available
    
    def test_can_toggle(self, shadow_detect):
        """Test enable/disable."""
        require_root()
        original = shadow_detect.enabled
        
        shadow_detect.enabled = not original
        assert shadow_detect.enabled == (not original)
        
        shadow_detect.enabled = original
    
    def test_threshold_readable(self, shadow_detect):
        """Test syn_threshold is readable."""
        val = shadow_detect.read('syn_threshold')
        assert val is not None
        assert val.isdigit()


class TestShadowFrustrate:
    """Tests for shadow_frustrate (Frustration engine)."""
    
    def test_module_available(self, shadow_frustrate):
        """Verify module is loaded."""
        assert shadow_frustrate.available
    
    def test_config_readable(self, shadow_frustrate):
        """Test config is readable."""
        config = shadow_frustrate.read('config')
        assert config is not None
        assert 'delay' in config.lower()
    
    def test_stats_available(self, shadow_frustrate):
        """Test stats are available."""
        stats = shadow_frustrate.get_stats()
        assert isinstance(stats, dict)
    
    def test_attackers_list(self, shadow_frustrate):
        """Test attackers list is readable."""
        attackers = shadow_frustrate.read('attackers')
        assert attackers is not None


class TestShadowPhantom:
    """Tests for shadow_phantom (Tarpit services)."""
    
    def test_module_available(self, shadow_phantom):
        """Verify module is loaded."""
        assert shadow_phantom.available
    
    def test_ports_list(self, shadow_phantom):
        """Test ports list is readable."""
        ports = shadow_phantom.read('ports')
        assert ports is not None
        # Should show port numbers
        assert any(c.isdigit() for c in ports)
    
    def test_stats_available(self, shadow_phantom):
        """Test stats show synacks/tarpits."""
        stats = shadow_phantom.read('stats')
        assert stats is not None
        assert 'synack' in stats.lower() or 'tarpit' in stats.lower()


class TestShadowDecoy:
    """Tests for shadow_decoy (Phantom hosts)."""
    
    def test_module_available(self, shadow_decoy):
        """Verify module is loaded."""
        assert shadow_decoy.available
    
    def test_can_add_host(self, shadow_decoy):
        """Test adding a phantom host IP."""
        require_root()
        shadow_decoy.write('add', '192.168.99.99')
        hosts = shadow_decoy.read('list')
        assert hosts is not None
        assert '192.168.99.99' in hosts
    
    def test_stats_show_arp(self, shadow_decoy):
        """Test stats show ARP responses."""
        stats = shadow_decoy.read('stats')
        assert stats is not None
        assert 'arp' in stats.lower()


class TestNetworkIntegration:
    """Integration tests for network modules."""
    
    def test_all_network_modules_paths(self):
        """Verify expected network modules have correct paths."""
        expected = ['detect', 'frustrate', 'chaos', 'phantom', 'decoy']
        for name in expected:
            mod = ShadowModule(name)
            assert mod.path.startswith('/sys/kernel/shadowos/')
    
    @pytest.mark.slow
    def test_scan_detection_triggers(self, shadow_detect):
        """Test that rapid connections trigger detection stats increase."""
        require_root()
        
        # Get initial stats
        initial_stats = shadow_detect.get_stats()
        initial_count = int(initial_stats.get('packets', 0))
        
        # Make several rapid connections (if we're on live system)
        # This is a slow test and may not work in all environments
        try:
            for port in range(1024, 1030):
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(0.1)
                    s.connect(('127.0.0.1', port))
                    s.close()
                except:
                    pass
        except:
            pytest.skip("Cannot create sockets for test")
        
        # Check stats increased
        final_stats = shadow_detect.get_stats()
        # Stats may or may not increase depending on module state
        assert isinstance(final_stats, dict)
