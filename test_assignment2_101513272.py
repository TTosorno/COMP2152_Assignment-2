import unittest
# Import components from the main assignment file
from assignment2_101513272 import PortScanner, common_ports

class TestPortScanner(unittest.TestCase):
    
    def test_scanner_initialization(self):
        """Test that the scanner initializes with correct target and empty results."""
        scanner = PortScanner("127.0.0.1")
        self.assertEqual(scanner.target, "127.0.0.1")
        self.assertEqual(scanner.scan_results, [])

    def test_get_open_ports_filters_correctly(self):
        """Test that get_open_ports only returns results with 'Open' status."""
        scanner = PortScanner("127.0.0.1")
        # Manually populate results as requested
        scanner.scan_results = [
            (22, "Open", "SSH"),
            (23, "Closed", "Telnet"),
            (80, "Open", "HTTP")
        ]
        open_ports = scanner.get_open_ports()
        self.assertEqual(len(open_ports), 2)

    def test_common_ports_dict(self):
        """Test the mapping in the common_ports dictionary."""
        self.assertEqual(common_ports[80], "HTTP")
        self.assertEqual(common_ports[22], "SSH")

    def test_invalid_target(self):
        """Test that the complex setter rejects empty strings."""
        scanner = PortScanner("127.0.0.1")
        # setter logic should trigger error message and not update value
        scanner.target = "" 
        self.assertEqual(scanner.target, "127.0.0.1")

if __name__ == "__main__":
    unittest.main()