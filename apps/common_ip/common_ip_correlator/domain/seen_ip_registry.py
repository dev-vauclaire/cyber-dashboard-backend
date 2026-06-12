from __future__ import annotations

from collections.abc import Iterable, Mapping
from copy import copy
from datetime import datetime

from common_ip_correlator.domain.common_ip_alert_source import CommonIpAlertSource
from common_ip_correlator.domain.ip_address import IpAddress


class SeenIpRegistry:
    # Responsabilite : conserver en memoire les IP deja vues et les resumes par source associes.

    def __init__(
        self,
        initial_state: Mapping[str, Iterable[CommonIpAlertSource]] | None = None,
    ) -> None:
        # Initialiser la structure memoire du correlator.
        self._seen_ips: dict[str, dict[int, CommonIpAlertSource]] = {}
        if initial_state is not None:
            for attacker_ip, source_summaries in initial_state.items():
                self.seed(attacker_ip, source_summaries)

    def seed(self, attacker_ip: str, source_summaries: Iterable[CommonIpAlertSource]) -> None:
        # Precharger une IP et ses resumes par source.
        normalized_ip = self._normalize_ip(attacker_ip)
        self._seen_ips[normalized_ip] = {
            summary.source_id: self._clone_source_summary(summary)
            for summary in source_summaries
        }

    def contains_ip(self, attacker_ip: str) -> bool:
        # Verifier si une IP est deja connue du registre.
        return self._normalize_ip(attacker_ip) in self._seen_ips

    def contains_source(self, attacker_ip: str, source_id: int) -> bool:
        # Verifier si une source a deja vu cette IP.
        normalized_ip = self._normalize_ip(attacker_ip)
        return int(source_id) in self._seen_ips.get(normalized_ip, {})

    def register_source(self, attacker_ip: str, source_id: int, occurred_at: datetime) -> None:
        # Integrer une nouvelle attaque dans le resume memoire d'une IP/source.
        normalized_ip = self._normalize_ip(attacker_ip)
        source_summaries = self._seen_ips.setdefault(normalized_ip, {})
        existing_summary = source_summaries.get(int(source_id))

        if existing_summary is None:
            source_summaries[int(source_id)] = CommonIpAlertSource(
                source_id=int(source_id),
                first_seen_at=occurred_at,
                last_seen_at=occurred_at,
                hit_count=1,
            )
            return

        existing_summary.first_seen_at = min(existing_summary.first_seen_at, occurred_at)
        existing_summary.last_seen_at = max(existing_summary.last_seen_at, occurred_at)
        existing_summary.increment_hit_count()

    def get_sources(self, attacker_ip: str) -> set[int]:
        # Retourner la liste des sources connues pour une IP.
        normalized_ip = self._normalize_ip(attacker_ip)
        return set(self._seen_ips.get(normalized_ip, {}))

    def get_source_summaries(self, attacker_ip: str) -> list[CommonIpAlertSource]:
        # Retourner les resumes connus pour une IP.
        normalized_ip = self._normalize_ip(attacker_ip)
        source_summaries = self._seen_ips.get(normalized_ip, {})
        return [
            self._clone_source_summary(source_summaries[source_id])
            for source_id in sorted(source_summaries)
        ]

    def preview_source_summaries(
        self,
        attacker_ip: str,
        *,
        source_id: int,
        occurred_at: datetime,
    ) -> list[CommonIpAlertSource]:
        # Projeter l'etat memoire d'une IP apres integration d'une nouvelle attaque, sans muter le registre.
        projected_summaries = {
            summary.source_id: self._clone_source_summary(summary)
            for summary in self.get_source_summaries(attacker_ip)
        }
        existing_summary = projected_summaries.get(int(source_id))

        if existing_summary is None:
            projected_summaries[int(source_id)] = CommonIpAlertSource(
                source_id=int(source_id),
                first_seen_at=occurred_at,
                last_seen_at=occurred_at,
                hit_count=1,
            )
        else:
            existing_summary.first_seen_at = min(existing_summary.first_seen_at, occurred_at)
            existing_summary.last_seen_at = max(existing_summary.last_seen_at, occurred_at)
            existing_summary.increment_hit_count()

        return [
            projected_summaries[current_source_id]
            for current_source_id in sorted(projected_summaries)
        ]

    def snapshot(self) -> dict[str, dict[int, CommonIpAlertSource]]:
        # Retourner une copie de l'etat memoire courant.
        return {
            attacker_ip: {
                source_id: self._clone_source_summary(summary)
                for source_id, summary in source_summaries.items()
            }
            for attacker_ip, source_summaries in self._seen_ips.items()
        }

    @staticmethod
    def _normalize_ip(attacker_ip: str) -> str:
        return IpAddress(attacker_ip).normalize()

    @staticmethod
    def _clone_source_summary(source_summary: CommonIpAlertSource) -> CommonIpAlertSource:
        return copy(source_summary)
