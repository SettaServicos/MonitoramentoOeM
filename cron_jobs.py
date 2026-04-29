import logging
import sys

from main import (
    MonitorService,
    PVOP_BASE_URL,
    PVOP_EMAIL,
    PVOP_PASSWORD,
    PVOperation,
    validate_config,
)


def gerar_relatorio_semanal():
    validate_config()
    api_rele = PVOperation(email=PVOP_EMAIL, password=PVOP_PASSWORD, base_url=PVOP_BASE_URL)
    api_inv = PVOperation(email=PVOP_EMAIL, password=PVOP_PASSWORD, base_url=PVOP_BASE_URL)
    service = MonitorService(api_rele, api_inv)
    service._load_state()
    return service.gerar_relatorio_semanal()


def main():
    schedule_time = sys.argv[1]

    logging.info("- - - Sync Schedule Start")

    if schedule_time == "5:00":
        gerar_relatorio_semanal()

    logging.info("- - - Sync Schedule End")


if __name__ == "__main__":
    main()
