# tests/test_alerts.py
import unittest
from unittest.mock import patch
import os
from alerts.notifier import trigger_alert

class TestAlertNotifier(unittest.TestCase):
    
    @patch('alerts.notifier.notification.notify')
    def test_trigger_alert(self, mock_notify):
        """Test that triggering an alert executes correctly and handles notifications."""
        suspicious_ip = "192.168.1.50"
        old_mac = "AA:BB:CC:DD:EE:FF"
        new_mac = "11:22:33:44:55:66"
        
        # Ensure trigger_alert runs without throwing errors
        try:
            trigger_alert(suspicious_ip, old_mac, new_mac, reason="Unit Test Spoofing")
        except Exception as e:
            self.fail(f"trigger_alert raised an unexpected exception: {e}")
        
        # Verify that the desktop notification function was called
        mock_notify.assert_called_once()
        
        # Verify that the alerts.log file was successfully created/written to
        self.assertTrue(os.path.exists("alerts.log"))

if __name__ == '__main__':
    unittest.main()