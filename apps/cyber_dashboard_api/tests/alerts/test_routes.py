"""Tests des routes /api/alerts/common-ips."""

from __future__ import annotations

import unittest
from datetime import timedelta

from cyber_dashboard_api.api.errors import BadRequestError, NotFoundError
from cyber_dashboard_api.api.routes.alerts import (
    get_common_ip_alert_detail,
    list_common_ip_alerts,
    send_common_ip_alert_email,
    validate_source_ids,
)
from cyber_dashboard_api.api.schemas import AlertEmailRequestSchema

from tests.common import dump_schema, fixed_now


class FakeAlertRepository:
    """Repository fake pour les routes d'alertes communes."""

    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []

    def count_common_ip_alerts(
        self,
        *,
        source_ids: list[int] | None,
        last_seen_from: object,
        last_seen_to: object,
        min_distinct_source_count: int | None,
    ) -> int:
        self.calls.append(
            {
                "method": "count",
                "source_ids": source_ids,
                "last_seen_from": last_seen_from,
                "last_seen_to": last_seen_to,
                "min_distinct_source_count": min_distinct_source_count,
            }
        )
        return 3

    def list_common_ip_alerts(
        self,
        *,
        limit: int,
        offset: int,
        source_ids: list[int] | None,
        last_seen_from: object,
        last_seen_to: object,
        min_distinct_source_count: int | None,
    ) -> list[dict[str, object]]:
        self.calls.append(
            {
                "method": "list",
                "limit": limit,
                "offset": offset,
                "source_ids": source_ids,
                "last_seen_from": last_seen_from,
                "last_seen_to": last_seen_to,
                "min_distinct_source_count": min_distinct_source_count,
            }
        )
        return [
            {
                "id": 8,
                "attacker_ip": "78.128.112.74/32",
                "distinct_source_count": 2,
                "first_seen_at": fixed_now() - timedelta(days=2),
                "last_seen_at": fixed_now(),
            }
        ]

    def get_alert_detail_by_alert_id(self, alert_id: int) -> list[dict[str, object]]:
        self.calls.append({"method": "detail", "alert_id": alert_id})
        if alert_id == 404:
            return []
        return [
            {
                "attacker_ip": "78.128.112.74/32",
                "source_id": 1,
                "source_name": "OGO Paris",
                "sensor_type_code": "waf",
                "collector_type": "ogo",
                "domain_name": "paris.example",
                "external_id": None,
                "first_seen_at": fixed_now() - timedelta(days=2),
                "last_seen_at": fixed_now() - timedelta(days=1),
                "hit_count": 4,
            },
            {
                "attacker_ip": "78.128.112.74/32",
                "source_id": 2,
                "source_name": "Lurio Lyon",
                "sensor_type_code": "lurio",
                "collector_type": "serenicity",
                "domain_name": None,
                "external_id": "lurio-2",
                "first_seen_at": fixed_now() - timedelta(days=3),
                "last_seen_at": fixed_now(),
                "hit_count": 7,
            },
        ]


class FakeAlertEmailService:
    """Service fake pour la route d'envoi manuel."""

    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []

    def send_alert_email(
        self,
        *,
        alert_id: int,
        payload: AlertEmailRequestSchema,
    ) -> dict[str, object]:
        self.calls.append({"alert_id": alert_id, "payload": payload})
        return {
            "alert_id": alert_id,
            "recipient": payload.recipient,
            "sent": True,
        }


class AlertRoutesTestCase(unittest.TestCase):
    """Couvre la liste et le detail des alertes communes."""

    def setUp(self) -> None:
        self.repository = FakeAlertRepository()

    def test_validate_source_ids_rejects_non_positive_values(self) -> None:
        with self.assertRaises(BadRequestError) as context:
            validate_source_ids([1, 0])

        self.assertEqual(context.exception.code, "invalid_source_id")

    def test_list_common_ip_alerts_returns_pagination_and_items(self) -> None:
        response = list_common_ip_alerts(
            page=2,
            limit=10,
            source_id=[1, 2],
            from_at=fixed_now() - timedelta(days=7),
            to_at=fixed_now(),
            min_distinct_source_count=2,
            alert_repository=self.repository,
        )

        payload = dump_schema(response)
        self.assertEqual(payload["pagination"]["page"], 2)
        self.assertEqual(payload["pagination"]["page_size"], 10)
        self.assertEqual(payload["pagination"]["total_items"], 3)
        self.assertEqual(payload["items"][0]["attacker_ip"], "78.128.112.74")
        self.assertEqual(self.repository.calls[0]["method"], "count")
        self.assertEqual(self.repository.calls[1]["offset"], 10)

    def test_get_common_ip_alert_detail_returns_sources(self) -> None:
        response = get_common_ip_alert_detail(
            alert_id=8,
            alert_repository=self.repository,
        )

        payload = dump_schema(response)
        self.assertEqual(payload["attacker_ip"], "78.128.112.74")
        self.assertEqual(len(payload["sources"]), 2)
        self.assertEqual(payload["sources"][0]["source_name"], "OGO Paris")
        self.assertEqual(payload["sources"][0]["sensor_type_code"], "waf")
        self.assertEqual(payload["sources"][0]["collector_type"], "ogo")
        self.assertEqual(payload["sources"][0]["domain_name"], "paris.example")
        self.assertIsNone(payload["sources"][0]["external_id"])

    def test_get_common_ip_alert_detail_raises_not_found_when_missing(self) -> None:
        with self.assertRaises(NotFoundError) as context:
            get_common_ip_alert_detail(
                alert_id=404,
                alert_repository=self.repository,
            )

        self.assertEqual(context.exception.code, "common_ip_alert_not_found")

    def test_send_common_ip_alert_email_delegates_to_service(self) -> None:
        service = FakeAlertEmailService()
        payload = AlertEmailRequestSchema(
            recipient="abuse@example.net",
            subject="Alerte IP commune",
            body="Bonjour",
        )

        response = send_common_ip_alert_email(
            payload=payload,
            alert_id=8,
            alert_email_service=service,
        )

        body = dump_schema(response)
        self.assertTrue(body["sent"])
        self.assertEqual(body["recipient"], "abuse@example.net")
        self.assertEqual(service.calls[0]["alert_id"], 8)
