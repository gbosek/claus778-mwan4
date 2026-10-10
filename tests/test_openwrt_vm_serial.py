#!/usr/bin/env python3
"""Regression for OpenWrt serial-command assembly (CI #37753230505)."""
import pathlib
import subprocess
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from openwrt_vm import serial_command_line, strip_ansi

class SerialCommands(unittest.TestCase):
    def test_strip_ansi_from_colored_route_device(self):
        route = "198.18.0.1 dev \x1b[1;36meth2\x1b[0m table pbr_dhcpwan"
        self.assertEqual(
            strip_ansi(route), "198.18.0.1 dev eth2 table pbr_dhcpwan"
        )

    def test_foreground_checks_exit_status(self):
        line = serial_command_line("false", "__TEST_")
        self.assertIn("false; rc=$?;", line)
        run = subprocess.run(["sh", "-c", line], capture_output=True, text=True, check=True)
        self.assertIn("__TEST_1", run.stdout)

    def test_background_no_semicolon_after_ampersand(self):
        command = "(/bin/true >/dev/null 2>&1) &"
        line = serial_command_line(command, "__TEST_")
        self.assertNotIn("&;", line)
        self.assertIn("& rc=$?;", line)
        run = subprocess.run(["sh", "-c", line], capture_output=True, text=True, check=True)
        self.assertIn("__TEST_0", run.stdout)

    def test_existing_semicolon(self):
        line = serial_command_line("true;", "__TEST_")
        self.assertNotIn(";;", line)
        run = subprocess.run(["sh", "-c", line], capture_output=True, text=True, check=True)
        self.assertIn("__TEST_0", run.stdout)

    def test_tty_length_guard(self):
        with self.assertRaisesRegex(ValueError, "too long"):
            serial_command_line("echo " + "x" * 230, "__TEST_")
        with self.assertRaisesRegex(ValueError, "empty"):
            serial_command_line("", "__TEST_")

if __name__ == "__main__":
    unittest.main()
