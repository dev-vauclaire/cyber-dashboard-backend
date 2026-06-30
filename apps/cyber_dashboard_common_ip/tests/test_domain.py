from __future__ import annotations

import unittest
from datetime import datetime

from cyber_dashboard_common_ip.domain.common_ip_alert_source import CommonIpAlertSource
from cyber_dashboard_common_ip.domain.ip_address import IpAddress
from cyber_dashboard_common_ip.domain.seen_ip_registry import SeenIpRegistry


class IpAddressTests(unittest.TestCase):
    def test_normalize_ipv4(self) -> None:
        ip_address = IpAddress(" 2001:0db8:0000:0000:0000:ff00:0042:8329 ")

        self.assertTrue(ip_address.is_valid())
        self.assertEqual(ip_address.normalize(), "2001:db8::ff00:42:8329")

    def test_normalize_inet_host_with_prefix(self) -> None:
        ip_address = IpAddress("192.0.2.55/32")

        self.assertTrue(ip_address.is_valid())
        self.assertEqual(ip_address.normalize(), "192.0.2.55")

    def test_normalize_ipv6_inet_host_with_prefix(self) -> None:
        ip_address = IpAddress("2001:db8::42/128")

        self.assertTrue(ip_address.is_valid())
        self.assertEqual(ip_address.normalize(), "2001:db8::42")

    def test_invalid_ip_returns_false(self) -> None:
        ip_address = IpAddress("not-an-ip")

        self.assertFalse(ip_address.is_valid())
        with self.assertRaises(ValueError):
            ip_address.normalize()


class SeenIpRegistryTests(unittest.TestCase):
    def test_register_and_lookup_ip(self) -> None:
        registry = SeenIpRegistry()

        registry.register_source("10.0.0.1", 12, datetime(2026, 4, 16, 10, 0, 0))

        self.assertTrue(registry.contains_ip("10.0.0.1"))
        self.assertTrue(registry.contains_source("10.0.0.1", 12))

    def test_same_source_detection(self) -> None:
        registry = SeenIpRegistry(
            {
                "10.0.0.1": [
                    CommonIpAlertSource(
                        source_id=1,
                        first_seen_at=datetime(2026, 4, 16, 10, 0, 0),
                        last_seen_at=datetime(2026, 4, 16, 10, 0, 0),
                        hit_count=1,
                    )
                ]
            }
        )

        self.assertTrue(registry.contains_source("10.0.0.1", 1))
        self.assertFalse(registry.contains_source("10.0.0.1", 2))

    def test_different_sources_are_merged(self) -> None:
        registry = SeenIpRegistry(
            {
                "10.0.0.1": [
                    CommonIpAlertSource(
                        source_id=1,
                        first_seen_at=datetime(2026, 4, 16, 10, 0, 0),
                        last_seen_at=datetime(2026, 4, 16, 10, 0, 0),
                        hit_count=1,
                    )
                ]
            }
        )

        registry.register_source("10.0.0.1", 2, datetime(2026, 4, 16, 11, 0, 0))

        self.assertEqual(registry.get_sources("10.0.0.1"), {1, 2})

    def test_existing_source_updates_first_last_seen_and_hit_count(self) -> None:
        registry = SeenIpRegistry(
            {
                "10.0.0.1": [
                    CommonIpAlertSource(
                        source_id=1,
                        first_seen_at=datetime(2026, 4, 16, 10, 0, 0),
                        last_seen_at=datetime(2026, 4, 16, 11, 0, 0),
                        hit_count=2,
                    )
                ]
            }
        )

        registry.register_source("10.0.0.1", 1, datetime(2026, 4, 16, 12, 0, 0))

        source_summary = registry.get_source_summaries("10.0.0.1")[0]
        self.assertEqual(source_summary.first_seen_at, datetime(2026, 4, 16, 10, 0, 0))
        self.assertEqual(source_summary.last_seen_at, datetime(2026, 4, 16, 12, 0, 0))
        self.assertEqual(source_summary.hit_count, 3)
