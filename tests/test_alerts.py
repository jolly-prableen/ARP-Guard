# tests/test_alerts.py
import unittest
from unittest.mock import patch
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
        
    @patch('alerts.notifier.notification.notify', side_effect=RuntimeError("disabled"))
    def test_notification_failure_is_logged(self, mock_notify):
        """Desktop notification failures must not crash the alert callback."""
        with self.assertLogs('alerts.notifier', level='ERROR') as logs:
            trigger_alert("192.0.2.50", "00:00:00:00:00:01", "00:00:00:00:00:02")

        mock_notify.assert_called_once()
        self.assertIn('Desktop notification failed', '\n'.join(logs.output))

if __name__ == '__main__':
    unittest.main()
