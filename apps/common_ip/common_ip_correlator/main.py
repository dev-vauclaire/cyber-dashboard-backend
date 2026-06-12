"""
Copyright (c) 2026 Vauclaire

Licensed under the EUPL, Version 1.2
You may not use this work except in compliance with the Licence.
You may obtain a copy of the Licence at:

https://eupl.eu/
"""

from __future__ import annotations

import logging

from common_ip_correlator.config import CorrelatorConfig, get_settings
from common_ip_correlator.db import PostgresDatabase, get_database
from common_ip_correlator.repositories.alert_repository import AlertRepository
from common_ip_correlator.repositories.attack_repository import AttackRepository
from common_ip_correlator.repositories.state_repository import StateRepository
from common_ip_correlator.services.correlator import Correlator
from common_ip_correlator.services.state_loader import StateLoader


class CommonIpCorrelatorApp:
    # Responsabilite : assembler les composants techniques et lancer l'application.

    def __init__(self) -> None:
        # Initialiser le point d'entree de l'application.
        self._config: CorrelatorConfig | None = None
        self._database: PostgresDatabase | None = None
        self._correlator: Correlator | None = None

    def build_dependencies(self) -> Correlator:
        # Instancier la configuration, la connexion BDD, les repositories et les services.
        self._config = get_settings()

        logging.basicConfig(
            level=getattr(logging, self._config.log_level, logging.INFO),
            format="%(asctime)s %(levelname)s %(name)s %(message)s",
        )

        self._database = get_database()
        attack_repository = AttackRepository(self._database)
        alert_repository = AlertRepository(self._database)
        state_repository = StateRepository(self._database)
        state_loader = StateLoader(state_repository)
        self._correlator = Correlator(
            self._config,
            self._database,
            attack_repository,
            alert_repository,
            state_loader,
        )
        return self._correlator

    def run(self) -> None:
        # Demarrer le correlator principal.
        correlator = self._correlator or self.build_dependencies()
        correlator.run()


if __name__ == "__main__":
    # Lancer l'application depuis la ligne de commande.
    CommonIpCorrelatorApp().run()
