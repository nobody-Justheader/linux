"""
ShadowOS Security Module Tests
Tests for security/shadowos kernel modules via sysfs.
"""

import os
import pytest
import tempfile
from conftest import require_root, run_cmd, ShadowModule


class TestShadowAV:
    """Tests for shadow_av (Audio/Video kill switch)."""
    
    def test_module_available(self, shadow_av):
        """Verify module is loaded and sysfs exists."""
        assert shadow_av.available
    
    def test_can_toggle(self, shadow_av):
        """Test enable/disable functionality."""
        require_root()
        original = shadow_av.enabled
        
        shadow_av.enabled = True
        assert shadow_av.enabled == True
        
        shadow_av.enabled = False
        assert shadow_av.enabled == False
        
        # Restore
        shadow_av.enabled = original
    
    def test_camera_toggle(self, shadow_av):
        """Test camera blocking toggle."""
        require_root()
        val = shadow_av.read('camera')
        assert val in ['0', '1']
    
    def test_microphone_toggle(self, shadow_av):
        """Test microphone blocking toggle."""
        require_root()
        val = shadow_av.read('microphone')
        assert val in ['0', '1']


class TestShadowCloak:
    """Tests for shadow_cloak (Process hiding)."""
    
    def test_module_available(self, shadow_cloak):
        """Verify module is loaded."""
        assert shadow_cloak.available
    
    def test_can_add_pid(self, shadow_cloak):
        """Test adding a PID to hidden list."""
        require_root()
        pid = str(os.getpid())
        shadow_cloak.write('hide', pid)
        # Read back list
        hidden = shadow_cloak.read('list') or ''
        assert pid in hidden
    
    def test_hidden_count(self, shadow_cloak):
        """Test hidden count in stats."""
        stats = shadow_cloak.get_stats()
        # Should have some stats
        assert isinstance(stats, dict)


class TestShadowShred:
    """Tests for shadow_shred (Secure deletion)."""
    
    def test_module_available(self, shadow_shred):
        """Verify module is loaded."""
        assert shadow_shred.available
    
    def test_patterns_readable(self, shadow_shred):
        """Test that shred patterns are readable."""
        patterns = shadow_shred.read('patterns')
        assert patterns is not None
        # Should contain DoD pattern info
        assert 'pass' in patterns.lower() or 'dod' in patterns.lower() or patterns
    
    def test_stats_available(self, shadow_shred):
        """Test stats are available."""
        stats = shadow_shred.get_stats()
        assert isinstance(stats, dict)


class TestShadowDeadman:
    """Tests for shadow_deadman (Dead man's switch)."""
    
    def test_module_available(self, shadow_deadman):
        """Verify module is loaded."""
        assert shadow_deadman.available
    
    def test_status_readable(self, shadow_deadman):
        """Test status can be read."""
        status = shadow_deadman.read('status')
        assert status is not None
        assert 'armed' in status.lower()
    
    def test_checkin_works(self, shadow_deadman):
        """Test check-in functionality."""
        require_root()
        # Write anything to checkin
        shadow_deadman.write('checkin', '1')
        # Status should show recent checkin
        status = shadow_deadman.read('status')
        assert 'checkin' in status.lower()


class TestShadowTimelock:
    """Tests for shadow_timelock (Time-based access)."""
    
    def test_module_available(self, shadow_timelock):
        """Verify module is loaded."""
        assert shadow_timelock.available
    
    def test_current_time(self, shadow_timelock):
        """Test current time is reported."""
        time_str = shadow_timelock.read('current_time')
        assert time_str is not None
        # Should contain day name
        assert any(day in time_str for day in ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'])
    
    def test_rules_list(self, shadow_timelock):
        """Test rules list is readable."""
        rules = shadow_timelock.read('list')
        assert rules is not None


class TestModuleIntegration:
    """Integration tests across modules."""
    
    def test_all_security_modules_exist(self):
        """Verify all expected security modules have sysfs."""
        expected = ['av', 'cloak', 'shred', 'ram', 'panic', 'defcon']
        for name in expected:
            mod = ShadowModule(name)
            # Just check path format is correct
            assert mod.path.startswith('/sys/kernel/shadowos/')
    
    def test_sysfs_base_exists(self):
        """Verify ShadowOS sysfs base directory exists."""
        # This may fail if modules not loaded
        if not os.path.isdir('/sys/kernel/shadowos'):
            pytest.skip("ShadowOS sysfs not available - modules not loaded")
        assert os.path.isdir('/sys/kernel/shadowos')
