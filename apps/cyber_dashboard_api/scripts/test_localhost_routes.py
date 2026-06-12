#!/usr/bin/env python3
"""Smoke tests HTTP pour l'API locale Cyber Dashboard."""

from __future__ import annotations

import argparse
import json
import sys
import uuid
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Callable, Iterable
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen


def default_date_range() -> tuple[str, str]:
    """Construit une plage ISO 8601 recente pour les routes statistiques."""
    now = datetime.now(UTC).replace(microsecond=0)
    start = (now - timedelta(days=7)).replace(hour=0, minute=0, second=0)
    return start.isoformat().replace("+00:00", "Z"), now.isoformat().replace("+00:00", "Z")


def next_color(current_color: str | None) -> str:
    """Retourne une couleur de test differente."""
    candidate = "#00FF00"
    if current_color == candidate:
        return "#2563EB"
    return candidate


def summarize_payload(payload: object) -> str:
    """Retourne un court resume lisible d'un payload HTTP."""
    if payload is None:
        return "No response body"
    try:
        text = json.dumps(payload, ensure_ascii=True, separators=(",", ":"))
    except TypeError:
        text = repr(payload)
    if len(text) <= 200:
        return text
    return f"{text[:197]}..."


@dataclass(slots=True)
class HttpResponse:
    """Reponse HTTP normalisee pour le script de smoke test."""

    status_code: int
    payload: object | None
    raw_body: str


@dataclass(slots=True)
class CheckResult:
    """Resultat final d'un controle de route."""

    name: str
    method: str
    path: str
    outcome: str
    actual_status: int | None
    expected_statuses: list[int]
    detail: str


class HttpClient:
    """Client HTTP JSON minimal base sur urllib."""

    def __init__(self, *, base_url: str, timeout_seconds: float) -> None:
        self._base_url = base_url.rstrip("/")
        self._timeout_seconds = timeout_seconds

    def request(
        self,
        *,
        method: str,
        path: str,
        query: dict[str, object] | None = None,
        body: dict[str, object] | None = None,
    ) -> HttpResponse:
        final_url = f"{self._base_url}{path}"
        if query:
            final_url = f"{final_url}?{urlencode(query, doseq=True)}"

        headers = {"Accept": "application/json"}
        data: bytes | None = None
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"

        request = Request(final_url, data=data, headers=headers, method=method)

        try:
            with urlopen(request, timeout=self._timeout_seconds) as response:
                raw_body = response.read().decode("utf-8")
                status_code = int(response.status)
        except HTTPError as exc:
            status_code = int(exc.code)
            raw_body = exc.read().decode("utf-8")
        except URLError as exc:
            raise RuntimeError(f"HTTP request failed for {method} {path}: {exc}") from exc

        payload: object | None = None
        if raw_body:
            try:
                payload = json.loads(raw_body)
            except json.JSONDecodeError:
                payload = raw_body

        return HttpResponse(status_code=status_code, payload=payload, raw_body=raw_body)


class ApiRouteSmokeRunner:
    """Execute des checks HTTP sur l'API locale."""

    def __init__(
        self,
        *,
        client: HttpClient,
        from_at: str,
        to_at: str,
        include_mutations: bool,
        include_external: bool,
        include_destructive: bool,
        cti_test_ip: str,
    ) -> None:
        self._client = client
        self._from_at = from_at
        self._to_at = to_at
        self._include_mutations = include_mutations
        self._include_external = include_external
        self._include_destructive = include_destructive
        self._cti_test_ip = cti_test_ip
        self._results: list[CheckResult] = []

    def results(self) -> list[CheckResult]:
        """Expose les resultats accumules."""
        return self._results

    def run(self) -> list[CheckResult]:
        """Execute la suite de smoke tests."""
        self._check_health()
        self._check_dashboard()
        source = self._check_sources()
        self._check_alerts()
        self._check_attacks(source)
        self._check_stats()
        cti_config = self._check_cti_config()
        self._check_smtp_config()
        attacks_collector_candidate = self._check_attacks_collector_config()
        retention_policy = self._check_retention_policies()
        if self._include_external:
            self._check_cti_enrichment()
            if attacks_collector_candidate is not None:
                self._check_attacks_collector_activation(attacks_collector_candidate)
            else:
                self._skip(
                    name="attacks_collector_config_activate",
                    method="POST",
                    path="/api/attacks-collector-config/{id}/activate",
                    detail="Skipped because no existing collector config with required secrets was discovered",
                )
        else:
            self._skip(
                name="cti_enrichment_all",
                method="GET",
                path="/api/cti-enrichment/*",
                detail="Skipped because --include-external was not provided",
            )

        if self._include_mutations:
            if source is not None:
                self._check_source_mutations(source)
            else:
                self._skip(
                    name="source_mutations",
                    method="PATCH",
                    path="/api/sources/{source_id}/*",
                    detail="Skipped because no source was returned by GET /api/sources",
                )

            if cti_config is not None:
                self._check_cti_config_mutations(cti_config)
            else:
                self._skip(
                    name="cti_config_mutations",
                    method="PATCH/POST/DELETE",
                    path="/api/cti-config/{code}/*",
                    detail="Skipped because no suitable CTI config was discovered",
                )

            if retention_policy is not None:
                self._check_retention_policy_mutation(retention_policy)
            else:
                self._skip(
                    name="retention_policy_patch",
                    method="PATCH",
                    path="/api/retention-policies/{target_table}",
                    detail="Skipped because no retention policy was returned by GET /api/retention-policies",
                )

            self._check_smtp_mutations()
            self._check_attacks_collector_mutations()
        else:
            self._skip(
                name="mutation_routes",
                method="MIXED",
                path="/api/*",
                detail="Skipped because --include-mutations was not provided",
            )

        if self._include_destructive:
            self._check_destructive_routes()
        else:
            self._skip(
                name="destructive_routes",
                method="MIXED",
                path="/api/*",
                detail="Skipped because --include-destructive was not provided",
            )

        return self._results

    def _record(
        self,
        *,
        name: str,
        method: str,
        path: str,
        outcome: str,
        actual_status: int | None,
        expected_statuses: Iterable[int],
        detail: str,
    ) -> None:
        self._results.append(
            CheckResult(
                name=name,
                method=method,
                path=path,
                outcome=outcome,
                actual_status=actual_status,
                expected_statuses=list(expected_statuses),
                detail=detail,
            )
        )

    def _pass(
        self,
        *,
        name: str,
        method: str,
        path: str,
        actual_status: int,
        expected_statuses: Iterable[int],
        detail: str,
    ) -> None:
        self._record(
            name=name,
            method=method,
            path=path,
            outcome="PASS",
            actual_status=actual_status,
            expected_statuses=expected_statuses,
            detail=detail,
        )

    def _fail(
        self,
        *,
        name: str,
        method: str,
        path: str,
        actual_status: int | None,
        expected_statuses: Iterable[int],
        detail: str,
    ) -> None:
        self._record(
            name=name,
            method=method,
            path=path,
            outcome="FAIL",
            actual_status=actual_status,
            expected_statuses=expected_statuses,
            detail=detail,
        )

    def _skip(
        self,
        *,
        name: str,
        method: str,
        path: str,
        detail: str,
    ) -> None:
        self._record(
            name=name,
            method=method,
            path=path,
            outcome="SKIP",
            actual_status=None,
            expected_statuses=[],
            detail=detail,
        )

    def _request_and_validate(
        self,
        *,
        name: str,
        method: str,
        path: str,
        expected_statuses: tuple[int, ...],
        query: dict[str, object] | None = None,
        body: dict[str, object] | None = None,
        validator: Callable[[object | None], str | None] | None = None,
    ) -> HttpResponse | None:
        try:
            response = self._client.request(
                method=method,
                path=path,
                query=query,
                body=body,
            )
        except RuntimeError as exc:
            self._fail(
                name=name,
                method=method,
                path=path,
                actual_status=None,
                expected_statuses=expected_statuses,
                detail=str(exc),
            )
            return None

        if response.status_code not in expected_statuses:
            self._fail(
                name=name,
                method=method,
                path=path,
                actual_status=response.status_code,
                expected_statuses=expected_statuses,
                detail=f"Unexpected response: {summarize_payload(response.payload)}",
            )
            return None

        if validator is not None:
            validation_error = validator(response.payload)
            if validation_error is not None:
                self._fail(
                    name=name,
                    method=method,
                    path=path,
                    actual_status=response.status_code,
                    expected_statuses=expected_statuses,
                    detail=validation_error,
                )
                return None

        self._pass(
            name=name,
            method=method,
            path=path,
            actual_status=response.status_code,
            expected_statuses=expected_statuses,
            detail=summarize_payload(response.payload),
        )
        return response

    def _check_health(self) -> None:
        self._request_and_validate(
            name="health",
            method="GET",
            path="/health",
            expected_statuses=(200,),
            validator=lambda payload: None
            if isinstance(payload, dict) and payload.get("status") == "ok"
            else "Expected {'status': 'ok'}",
        )

    def _check_dashboard(self) -> None:
        self._request_and_validate(
            name="dashboard_overview",
            method="GET",
            path="/api/dashboard/overview",
            expected_statuses=(200,),
            validator=lambda payload: None
            if isinstance(payload, dict)
            and {"total_attacks", "total_common_ip_alerts", "total_active_sources", "total_inactive_sources"} <= set(payload.keys())
            else "Missing expected dashboard keys",
        )

    def _check_sources(self) -> dict[str, object] | None:
        self._request_and_validate(
            name="sources_inventory",
            method="GET",
            path="/api/sources/inventory",
            expected_statuses=(200,),
            validator=lambda payload: None
            if isinstance(payload, dict) and isinstance(payload.get("items"), list)
            else "Expected an 'items' array",
        )

        response = self._request_and_validate(
            name="sources_list",
            method="GET",
            path="/api/sources",
            expected_statuses=(200,),
            validator=lambda payload: None
            if isinstance(payload, dict) and isinstance(payload.get("items"), list)
            else "Expected an 'items' array",
        )
        if response is None or not isinstance(response.payload, dict):
            return None
        items = response.payload.get("items")
        if not isinstance(items, list) or not items:
            return None
        first_item = items[0]
        return first_item if isinstance(first_item, dict) else None

    def _check_source_mutations(self, source: dict[str, object]) -> None:
        source_id = source.get("source_id")
        source_name = source.get("source_name")
        color = source.get("color")
        is_active = source.get("is_active")
        if not isinstance(source_id, int) or not isinstance(source_name, str):
            self._skip(
                name="source_mutations",
                method="PATCH",
                path="/api/sources/{source_id}/*",
                detail="Skipped because source payload is missing required fields",
            )
            return

        updated_name = f"{source_name} [smoke]"
        if updated_name == source_name:
            updated_name = f"{source_name} [smoke-2]"

        rename_path = f"/api/sources/{source_id}/name"
        response = self._request_and_validate(
            name="source_rename",
            method="PATCH",
            path=rename_path,
            expected_statuses=(200,),
            body={"source_name": updated_name},
            validator=lambda payload: None
            if isinstance(payload, dict) and payload.get("source_name") == updated_name
            else "The source name was not updated as expected",
        )
        if response is not None:
            self._client.request(
                method="PATCH",
                path=rename_path,
                body={"source_name": source_name},
            )

        if isinstance(is_active, bool):
            toggled_status = not is_active
            status_path = f"/api/sources/{source_id}/is_active"
            response = self._request_and_validate(
                name="source_update_status",
                method="PATCH",
                path=status_path,
                expected_statuses=(200,),
                body={"is_active": toggled_status},
                validator=lambda payload: None
                if isinstance(payload, dict) and payload.get("is_active") is toggled_status
                else "The source status was not updated as expected",
            )
            if response is not None:
                self._client.request(
                    method="PATCH",
                    path=status_path,
                    body={"is_active": is_active},
                )

        if isinstance(color, str):
            updated_color = next_color(color)
            color_path = f"/api/sources/{source_id}/color"
            response = self._request_and_validate(
                name="source_update_color",
                method="PATCH",
                path=color_path,
                expected_statuses=(200,),
                body={"color": updated_color},
                validator=lambda payload: None
                if isinstance(payload, dict) and payload.get("color") == updated_color
                else "The source color was not updated as expected",
            )
            if response is not None and isinstance(color, str):
                self._client.request(
                    method="PATCH",
                    path=color_path,
                    body={"color": color},
                )
        else:
            self._skip(
                name="source_update_color",
                method="PATCH",
                path=f"/api/sources/{source_id}/color",
                detail="Skipped because the current source color is null and the API has no route to restore it to null",
            )

    def _check_alerts(self) -> dict[str, object] | None:
        response = self._request_and_validate(
            name="alerts_common_ips_list",
            method="GET",
            path="/api/alerts/common-ips",
            expected_statuses=(200,),
            query={"page": 1, "limit": 10, "from": self._from_at, "to": self._to_at},
            validator=lambda payload: None
            if isinstance(payload, dict)
            and isinstance(payload.get("pagination"), dict)
            and isinstance(payload.get("items"), list)
            else "Expected 'pagination' and 'items' in the response",
        )
        if response is None or not isinstance(response.payload, dict):
            return None
        items = response.payload.get("items")
        if not isinstance(items, list) or not items:
            self._skip(
                name="alerts_common_ips_detail",
                method="GET",
                path="/api/alerts/common-ips/{alert_id}",
                detail="Skipped because the alerts list is empty",
            )
            return None

        first_item = items[0]
        if not isinstance(first_item, dict) or not isinstance(first_item.get("id"), int):
            return None

        alert_id = first_item["id"]
        self._request_and_validate(
            name="alerts_common_ips_detail",
            method="GET",
            path=f"/api/alerts/common-ips/{alert_id}",
            expected_statuses=(200,),
            validator=lambda payload: None
            if isinstance(payload, dict) and isinstance(payload.get("sources"), list)
            else "Expected a 'sources' array in the response",
        )
        return first_item

    def _check_attacks(self, source: dict[str, object] | None) -> None:
        query: dict[str, object] = {
            "page": 1,
            "page_size": 20,
            "from": self._from_at,
            "to": self._to_at,
        }
        if isinstance(source, dict) and isinstance(source.get("source_id"), int):
            query["source_id"] = source["source_id"]

        self._request_and_validate(
            name="attacks_list",
            method="GET",
            path="/api/attacks",
            expected_statuses=(200,),
            query=query,
            validator=lambda payload: None
            if isinstance(payload, dict)
            and isinstance(payload.get("pagination"), dict)
            and isinstance(payload.get("items"), list)
            else "Expected 'pagination' and 'items' in the response",
        )

    def _check_stats(self) -> None:
        base_query = {"from": self._from_at, "to": self._to_at}
        self._request_and_validate(
            name="stats_summary",
            method="GET",
            path="/api/stats/attacks/summary",
            expected_statuses=(200,),
            query=base_query,
            validator=lambda payload: None
            if isinstance(payload, dict) and "total_attacks" in payload
            else "Expected 'total_attacks' in the response",
        )
        self._request_and_validate(
            name="stats_by_source",
            method="GET",
            path="/api/stats/attacks/by-source",
            expected_statuses=(200,),
            query=base_query,
            validator=lambda payload: None
            if isinstance(payload, dict) and isinstance(payload.get("by_source"), list)
            else "Expected 'by_source' in the response",
        )
        self._request_and_validate(
            name="stats_by_source_timeseries",
            method="GET",
            path="/api/stats/attacks/by-source-timeseries",
            expected_statuses=(200,),
            query=base_query,
            validator=lambda payload: None
            if isinstance(payload, dict)
            and isinstance(payload.get("bucket_starts_utc"), list)
            and isinstance(payload.get("series"), list)
            else "Expected 'bucket_starts_utc' and 'series' in the response",
        )
        self._request_and_validate(
            name="stats_by_type",
            method="GET",
            path="/api/stats/attacks/by-type",
            expected_statuses=(200,),
            query=base_query,
            validator=lambda payload: None
            if isinstance(payload, dict) and isinstance(payload.get("items"), list)
            else "Expected 'items' in the response",
        )

    def _check_cti_config(self) -> dict[str, object] | None:
        response = self._request_and_validate(
            name="cti_config_list",
            method="GET",
            path="/api/cti-config",
            expected_statuses=(200,),
            validator=lambda payload: None
            if isinstance(payload, dict) and isinstance(payload.get("items"), list)
            else "Expected an 'items' array",
        )
        if response is None or not isinstance(response.payload, dict):
            return None
        items = response.payload.get("items")
        if not isinstance(items, list) or not items:
            return None

        selected: dict[str, object] | None = None
        for item in items:
            if isinstance(item, dict) and item.get("is_key_required") is False:
                selected = item
                break
        if selected is None and isinstance(items[0], dict):
            selected = items[0]
        if selected is None:
            return None

        code = selected.get("code")
        if isinstance(code, str):
            self._request_and_validate(
                name="cti_config_get",
                method="GET",
                path=f"/api/cti-config/{code}",
                expected_statuses=(200,),
                validator=lambda payload: None
                if isinstance(payload, dict) and payload.get("code") == code
                else "The returned CTI config does not match the requested code",
            )
        return selected

    def _check_cti_config_mutations(self, cti_config: dict[str, object]) -> None:
        code = cti_config.get("code")
        label = cti_config.get("label")
        is_active = cti_config.get("is_active")
        is_key_required = cti_config.get("is_key_required")
        if not isinstance(code, str) or not isinstance(label, str):
            return

        updated_label = f"{label} [smoke]"
        patch_path = f"/api/cti-config/{code}"
        response = self._request_and_validate(
            name="cti_config_patch",
            method="PATCH",
            path=patch_path,
            expected_statuses=(200,),
            body={"label": updated_label},
            validator=lambda payload: None
            if isinstance(payload, dict) and payload.get("label") == updated_label
            else "The CTI label was not updated as expected",
        )
        if response is not None:
            self._client.request(
                method="PATCH",
                path=patch_path,
                body={"label": label},
            )

        if is_key_required is False:
            activate_path = f"/api/cti-config/{code}/activate"
            deactivate_path = f"/api/cti-config/{code}/deactivate"
            delete_key_path = f"/api/cti-config/{code}/api-key"

            if is_active is False:
                response = self._request_and_validate(
                    name="cti_config_activate",
                    method="POST",
                    path=activate_path,
                    expected_statuses=(200,),
                    validator=lambda payload: None
                    if isinstance(payload, dict) and payload.get("is_active") is True
                    else "The CTI config was not activated as expected",
                )
                if response is not None:
                    self._client.request(method="POST", path=deactivate_path)
            else:
                response = self._request_and_validate(
                    name="cti_config_deactivate",
                    method="POST",
                    path=deactivate_path,
                    expected_statuses=(200,),
                    validator=lambda payload: None
                    if isinstance(payload, dict) and payload.get("is_active") is False
                    else "The CTI config was not deactivated as expected",
                )
                if response is not None:
                    self._client.request(method="POST", path=activate_path)

            self._request_and_validate(
                name="cti_config_delete_api_key",
                method="DELETE",
                path=delete_key_path,
                expected_statuses=(200,),
                validator=lambda payload: None
                if isinstance(payload, dict) and payload.get("has_api_key") is False
                else "The CTI config did not report API key removal",
            )
        else:
            self._skip(
                name="cti_config_stateful_routes",
                method="POST/DELETE",
                path=f"/api/cti-config/{code}/*",
                detail="Skipped because the discovered CTI config requires an API key",
            )

    def _check_cti_enrichment(self) -> None:
        enrichment_paths = (
            "/api/cti-enrichment/abuseipdb",
            "/api/cti-enrichment/ipdata",
            "/api/cti-enrichment/greynoise",
            "/api/cti-enrichment/rdap",
            "/api/cti-enrichment/shodan",
            "/api/cti-enrichment/virustotal",
        )
        for path in enrichment_paths:
            self._request_and_validate(
                name=path.rsplit("/", 1)[-1].replace("-", "_"),
                method="GET",
                path=path,
                expected_statuses=(200,),
                query={"ip_address": self._cti_test_ip},
                validator=lambda payload: None
                if isinstance(payload, dict)
                else "Expected a JSON object response",
            )

    def _check_smtp_config(self) -> None:
        self._request_and_validate(
            name="smtp_config_get",
            method="GET",
            path="/api/smtp-config",
            expected_statuses=(200,),
            validator=lambda payload: None
            if isinstance(payload, dict) and "is_active" in payload
            else "Expected an SMTP config object",
        )

    def _check_smtp_mutations(self) -> None:
        get_response = self._client.request(method="GET", path="/api/smtp-config")
        if not isinstance(get_response.payload, dict):
            self._fail(
                name="smtp_config_patch",
                method="PATCH",
                path="/api/smtp-config",
                actual_status=get_response.status_code,
                expected_statuses=(200,),
                detail="Could not load the SMTP config before mutation tests",
            )
            return

        original_name = get_response.payload.get("smtp_from_name")
        temporary_name = "Cyber Dashboard Smoke Test"
        patch_response = self._request_and_validate(
            name="smtp_config_patch",
            method="PATCH",
            path="/api/smtp-config",
            expected_statuses=(200,),
            body={"smtp_from_name": temporary_name},
            validator=lambda payload: None
            if isinstance(payload, dict) and payload.get("smtp_from_name") == temporary_name
            else "The SMTP config was not updated as expected",
        )
        if patch_response is not None:
            revert_body = {"smtp_from_name": original_name}
            self._client.request(method="PATCH", path="/api/smtp-config", body=revert_body)

        self._request_and_validate(
            name="smtp_config_put",
            method="PUT",
            path="/api/smtp-config",
            expected_statuses=(200,),
            body={"smtp_from_name": original_name},
            validator=lambda payload: None
            if isinstance(payload, dict)
            else "Expected an SMTP config object",
        )

    def _check_attacks_collector_config(self) -> dict[str, object] | None:
        response = self._request_and_validate(
            name="attacks_collector_config_list",
            method="GET",
            path="/api/attacks-collector-config",
            expected_statuses=(200,),
            validator=lambda payload: None
            if isinstance(payload, dict) and isinstance(payload.get("items"), list)
            else "Expected an 'items' array",
        )
        if response is None or not isinstance(response.payload, dict):
            return None
        items = response.payload.get("items")
        if not isinstance(items, list):
            return None

        for item in items:
            if not isinstance(item, dict):
                continue
            collector_type = item.get("collector_type")
            has_api_key = item.get("has_api_key") is True
            has_email = item.get("has_email") is True
            if collector_type == "serenicity" and has_api_key:
                return item
            if collector_type == "ogo" and has_api_key and has_email:
                return item
        return None

    def _check_attacks_collector_activation(
        self,
        collector_config: dict[str, object],
    ) -> None:
        config_id = collector_config.get("id")
        is_active = collector_config.get("is_active")
        if not isinstance(config_id, int):
            return

        response = self._request_and_validate(
            name="attacks_collector_config_activate",
            method="POST",
            path=f"/api/attacks-collector-config/{config_id}/activate",
            expected_statuses=(200,),
            validator=lambda payload: None
            if isinstance(payload, dict) and payload.get("is_active") is True
            else "The collector config was not activated as expected",
        )
        if response is not None and is_active is False:
            self._client.request(
                method="POST",
                path=f"/api/attacks-collector-config/{config_id}/deactivate",
            )

    def _check_attacks_collector_mutations(self) -> None:
        unique_suffix = uuid.uuid4().hex[:8]
        create_response = self._request_and_validate(
            name="attacks_collector_config_create",
            method="POST",
            path="/api/attacks-collector-config",
            expected_statuses=(201,),
            body={
                "name": f"smoke-serenicity-{unique_suffix}",
                "collector_type": "serenicity",
                "api_key": "smoke-test-api-key",
            },
            validator=lambda payload: None
            if isinstance(payload, dict) and payload.get("collector_type") == "serenicity"
            else "The collector config was not created as expected",
        )
        if create_response is None or not isinstance(create_response.payload, dict):
            return

        config_id = create_response.payload.get("id")
        if not isinstance(config_id, int):
            self._fail(
                name="attacks_collector_config_create",
                method="POST",
                path="/api/attacks-collector-config",
                actual_status=create_response.status_code,
                expected_statuses=(201,),
                detail="The created collector config did not return an integer id",
            )
            return

        try:
            self._request_and_validate(
                name="attacks_collector_config_get",
                method="GET",
                path=f"/api/attacks-collector-config/{config_id}",
                expected_statuses=(200,),
                validator=lambda payload: None
                if isinstance(payload, dict) and payload.get("id") == config_id
                else "The collector config could not be reloaded",
            )
            self._request_and_validate(
                name="attacks_collector_config_patch",
                method="PATCH",
                path=f"/api/attacks-collector-config/{config_id}",
                expected_statuses=(200,),
                body={"name": f"smoke-serenicity-{unique_suffix}-updated"},
                validator=lambda payload: None
                if isinstance(payload, dict) and str(payload.get("name", "")).endswith("-updated")
                else "The collector config name was not updated as expected",
            )
            self._request_and_validate(
                name="attacks_collector_config_deactivate",
                method="POST",
                path=f"/api/attacks-collector-config/{config_id}/deactivate",
                expected_statuses=(200,),
                validator=lambda payload: None
                if isinstance(payload, dict) and payload.get("is_active") is False
                else "The collector config was not deactivated as expected",
            )
            self._request_and_validate(
                name="attacks_collector_config_delete_api_key",
                method="DELETE",
                path=f"/api/attacks-collector-config/{config_id}/api-key",
                expected_statuses=(200,),
                validator=lambda payload: None
                if isinstance(payload, dict) and payload.get("has_api_key") is False
                else "The collector config still reports an API key",
            )
            self._request_and_validate(
                name="attacks_collector_config_delete_email",
                method="DELETE",
                path=f"/api/attacks-collector-config/{config_id}/email",
                expected_statuses=(200,),
                validator=lambda payload: None
                if isinstance(payload, dict) and payload.get("has_email") is False
                else "The collector config still reports an email",
            )
            self._request_and_validate(
                name="attacks_collector_config_request_inventory",
                method="POST",
                path=f"/api/attacks-collector-config/{config_id}/request-inventory",
                expected_statuses=(200,),
                validator=lambda payload: None
                if isinstance(payload, dict)
                and payload.get("attacks_collector_config_id") == config_id
                and payload.get("inventory_requested") is True
                else "The inventory request response is invalid",
            )

        finally:
            self._request_and_validate(
                name="attacks_collector_config_delete",
                method="DELETE",
                path=f"/api/attacks-collector-config/{config_id}",
                expected_statuses=(204,),
                validator=lambda payload: None,
            )

    def _check_retention_policies(self) -> dict[str, object] | None:
        response = self._request_and_validate(
            name="retention_policies_list",
            method="GET",
            path="/api/retention-policies",
            expected_statuses=(200,),
            validator=lambda payload: None
            if isinstance(payload, dict) and isinstance(payload.get("items"), list)
            else "Expected an 'items' array",
        )
        if response is None or not isinstance(response.payload, dict):
            return None
        items = response.payload.get("items")
        if not isinstance(items, list) or not items or not isinstance(items[0], dict):
            return None
        first_item = items[0]
        target_table = first_item.get("target_table")
        if isinstance(target_table, str):
            self._request_and_validate(
                name="retention_policies_get",
                method="GET",
                path=f"/api/retention-policies/{target_table}",
                expected_statuses=(200,),
                validator=lambda payload: None
                if isinstance(payload, dict) and payload.get("target_table") == target_table
                else "The retention policy could not be reloaded",
            )
        return first_item

    def _check_retention_policy_mutation(self, retention_policy: dict[str, object]) -> None:
        target_table = retention_policy.get("target_table")
        retention_days = retention_policy.get("retention_days")
        is_active = retention_policy.get("is_active")
        if not isinstance(target_table, str) or not isinstance(retention_days, int) or not isinstance(is_active, bool):
            return

        updated_days = retention_days + 1
        updated_active = not is_active
        path = f"/api/retention-policies/{target_table}"
        response = self._request_and_validate(
            name="retention_policies_patch",
            method="PATCH",
            path=path,
            expected_statuses=(200,),
            body={"retention_days": updated_days, "is_active": updated_active},
            validator=lambda payload: None
            if isinstance(payload, dict)
            and payload.get("retention_days") == updated_days
            and payload.get("is_active") is updated_active
            else "The retention policy was not updated as expected",
        )
        if response is not None:
            self._client.request(
                method="PATCH",
                path=path,
                body={"retention_days": retention_days, "is_active": is_active},
            )

    def _check_destructive_routes(self) -> None:
        if self._include_external:
            self._request_and_validate(
                name="smtp_config_activate",
                method="POST",
                path="/api/smtp-config/activate",
                expected_statuses=(200,),
                validator=lambda payload: None
                if isinstance(payload, dict) and payload.get("is_active") is True
                else "The SMTP config was not activated as expected",
            )
        else:
            self._skip(
                name="smtp_config_activate",
                method="POST",
                path="/api/smtp-config/activate",
                detail="Skipped because --include-external was not provided",
            )

        self._request_and_validate(
            name="smtp_config_deactivate",
            method="POST",
            path="/api/smtp-config/deactivate",
            expected_statuses=(200,),
            validator=lambda payload: None
            if isinstance(payload, dict) and payload.get("is_active") is False
            else "The SMTP config was not deactivated as expected",
        )
        self._request_and_validate(
            name="smtp_config_delete_password",
            method="DELETE",
            path="/api/smtp-config/password",
            expected_statuses=(200,),
            validator=lambda payload: None
            if isinstance(payload, dict) and payload.get("has_smtp_password") is False
            else "The SMTP password was not deleted as expected",
        )


def build_report(results: list[CheckResult]) -> dict[str, object]:
    """Construit le rapport final serialisable en JSON."""
    summary = {"PASS": 0, "FAIL": 0, "SKIP": 0}
    for result in results:
        summary[result.outcome] += 1
    return {
        "generated_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "summary": summary,
        "results": [asdict(result) for result in results],
    }


def print_report(report: dict[str, object]) -> None:
    """Affiche un compte rendu texte lisible."""
    summary = report["summary"]
    print(
        "Summary:"
        f" PASS={summary['PASS']}"
        f" FAIL={summary['FAIL']}"
        f" SKIP={summary['SKIP']}"
    )
    print()
    print("Checks:")
    for result in report["results"]:
        expected = ",".join(str(code) for code in result["expected_statuses"]) or "-"
        actual = result["actual_status"] if result["actual_status"] is not None else "-"
        print(
            f"[{result['outcome']}] {result['method']:>10} {result['path']}"
            f" | expected={expected} actual={actual}"
        )
        print(f"  {result['detail']}")


def parse_args() -> argparse.Namespace:
    """Parse les options CLI du script."""
    from_at, to_at = default_date_range()
    parser = argparse.ArgumentParser(
        description="Teste les routes HTTP de cyber_dashboard_api sur localhost.",
    )
    parser.add_argument(
        "--base-url",
        default="http://127.0.0.1:8000",
        help="URL de base de l'API a tester.",
    )
    parser.add_argument(
        "--from",
        dest="from_at",
        default=from_at,
        help="Borne basse ISO 8601 pour les routes statistiques et attaques.",
    )
    parser.add_argument(
        "--to",
        dest="to_at",
        default=to_at,
        help="Borne haute ISO 8601 pour les routes statistiques et attaques.",
    )
    parser.add_argument(
        "--cti-test-ip",
        default="8.8.8.8",
        help="Adresse IP de test pour les routes d'enrichissement CTI.",
    )
    parser.add_argument(
        "--include-mutations",
        action="store_true",
        help="Active les routes PATCH/POST/DELETE revertibles.",
    )
    parser.add_argument(
        "--include-external",
        action="store_true",
        help="Active les routes qui appellent des services externes.",
    )
    parser.add_argument(
        "--include-destructive",
        action="store_true",
        help="Inclut les routes destructives dans le rapport. A utiliser uniquement dans un environnement local ou de recette maitrisé.",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help="Timeout HTTP unitaire en secondes.",
    )
    parser.add_argument(
        "--report-file",
        type=Path,
        default=None,
        help="Chemin optionnel du rapport JSON a ecrire.",
    )
    return parser.parse_args()


def main() -> int:
    """Point d'entree du script CLI."""
    args = parse_args()
    client = HttpClient(base_url=args.base_url, timeout_seconds=args.timeout)
    runner = ApiRouteSmokeRunner(
        client=client,
        from_at=args.from_at,
        to_at=args.to_at,
        include_mutations=args.include_mutations,
        include_external=args.include_external,
        include_destructive=args.include_destructive,
        cti_test_ip=args.cti_test_ip,
    )
    report = build_report(runner.run())
    print_report(report)

    if args.report_file is not None:
        args.report_file.parent.mkdir(parents=True, exist_ok=True)
        args.report_file.write_text(
            json.dumps(report, indent=2, ensure_ascii=True),
            encoding="utf-8",
        )

    return 1 if report["summary"]["FAIL"] else 0


if __name__ == "__main__":
    sys.exit(main())
