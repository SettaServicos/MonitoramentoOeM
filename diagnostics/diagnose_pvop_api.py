#!/usr/bin/env python
"""Diagnostico controlado da API PVOperation.

Uso seguro:
  python diagnostics/diagnose_pvop_api.py --date 2026-05-14 --start 15:00 --end 16:00
  python diagnostics/diagnose_pvop_api.py --plant "Magnum Tires" --endpoint day_inverter
  python diagnostics/diagnose_pvop_api.py --plant-id 123 --endpoint both

O script:
- usa as mesmas variaveis de ambiente e a mesma classe PVOperationAPI do main.py;
- nao envia Teams;
- nao altera state;
- nao imprime credenciais.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter
from datetime import datetime, time as dtime, timedelta
from pathlib import Path
from typing import Any


DEFAULT_TARGETS = [
    "Setta Energia",
    "SETGE7.BON.6880.LT01",
    "SETGE7.BON.6880.LT03",
    "ECO3.INA.2500.8 L15",
    "Magnum Tires",
    "Noe",
    "Noé",
    "B&H Filial L90",
]


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _load_main():
    root = _repo_root()
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))
    import main  # noqa: PLC0415

    return main


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Diagnostico real de day_inverter/day_relay na PVOperation")
    parser.add_argument("--plant", action="append", default=[], help="Nome ou trecho do nome da usina. Pode repetir.")
    parser.add_argument("--plant-id", action="append", default=[], help="ID exato da usina. Pode repetir.")
    parser.add_argument("--date", default=datetime.now().strftime("%Y-%m-%d"), help="Data consultada, formato YYYY-MM-DD.")
    parser.add_argument("--start", default="15:00", help="Inicio da janela local, formato HH:MM.")
    parser.add_argument("--end", default="16:00", help="Fim da janela local, formato HH:MM.")
    parser.add_argument(
        "--endpoint",
        choices=["day_inverter", "day_relay", "both"],
        default="both",
        help="Endpoint a diagnosticar.",
    )
    parser.add_argument("--max-plants", type=int, default=20, help="Limite de usinas diagnosticadas.")
    parser.add_argument("--show-sample", type=int, default=2, help="Quantidade de amostras sanitizadas por endpoint.")
    return parser.parse_args()


def _parse_dt(date_text: str, time_text: str) -> datetime:
    return datetime.strptime(f"{date_text} {time_text}", "%Y-%m-%d %H:%M")


def _safe_bool_env(name: str) -> str:
    return f"{name}: {bool(os.environ.get(name))}"


def _json_type(value: Any) -> str:
    return type(value).__name__


def _raw_size(resp) -> int:
    try:
        return len(resp.content or b"")
    except Exception:
        return 0


def _sanitize_sample(item: Any) -> Any:
    if not isinstance(item, dict):
        return type(item).__name__
    out = {}
    for key in ("id", "idinversor", "idrele", "nome"):
        if key in item:
            out[key] = item.get(key)
    conteudo = item.get("conteudojson")
    if isinstance(conteudo, dict):
        safe_conteudo = {}
        for key in ("tsleitura", "Inversor", "esn", "Pac", "PAC"):
            if key in conteudo:
                safe_conteudo[key] = conteudo.get(key)
        relay_keys = sorted(k for k in conteudo if str(k).lower().startswith("r"))[:10]
        for key in relay_keys:
            safe_conteudo[key] = conteudo.get(key)
        out["conteudojson"] = safe_conteudo
    else:
        out["conteudojson_type"] = type(conteudo).__name__
    return out


def _select_plants(plants: list[dict], names: list[str], ids: list[str], max_plants: int) -> list[dict]:
    selected: list[dict] = []
    selected_ids = set()
    id_targets = {str(x).strip() for x in ids if str(x).strip()}
    name_targets = [str(x).strip().lower() for x in names if str(x).strip()]
    if not id_targets and not name_targets:
        name_targets = [x.lower() for x in DEFAULT_TARGETS]

    for plant in plants:
        pid = str(plant.get("id", "")).strip()
        pname = str(plant.get("nome", "")).strip()
        pname_l = pname.lower()
        matched = pid in id_targets or any(target in pname_l for target in name_targets)
        if matched and pid not in selected_ids:
            selected.append(plant)
            selected_ids.add(pid)
        if len(selected) >= max_plants:
            break
    return selected


def _call_day_raw(main, api, endpoint: str, plant_id: int, date_dt: datetime):
    payload = {"id": int(plant_id), "date": date_dt.strftime("%Y-%m-%d")}
    url = f"{api.base_url}/{endpoint}"
    started = datetime.now()
    try:
        resp = api.session.request("post", url, headers=api.headers, json=payload, timeout=30)
    except Exception as exc:
        return {
            "endpoint": endpoint,
            "payload": payload,
            "request_started_local": started.isoformat(timespec="seconds"),
            "request_error": type(exc).__name__,
            "request_error_text": str(exc)[:300],
        }

    info = {
        "endpoint": endpoint,
        "payload": payload,
        "request_started_local": started.isoformat(timespec="seconds"),
        "status_http": resp.status_code,
        "content_type": resp.headers.get("Content-Type", ""),
        "raw_size_bytes": _raw_size(resp),
    }
    try:
        info["json"] = resp.json()
        info["json_valid"] = True
        info["json_type"] = _json_type(info["json"])
    except Exception as exc:
        info["json"] = None
        info["json_valid"] = False
        info["json_error"] = type(exc).__name__
        text = getattr(resp, "text", "") or ""
        info["text_prefix"] = text[:200].replace("\n", "\\n")
    return info


def _analyze_records(main, endpoint: str, data: Any, inicio: datetime, fim: datetime, plant_name: str) -> dict:
    result = {
        "raw_json_type": _json_type(data),
        "raw_record_count": len(data) if isinstance(data, list) else None,
        "has_conteudojson": False,
        "has_tsleitura": False,
        "accepted_by_iterar_registros_api_dia": 0,
        "discard_reasons": Counter(),
        "accepted_in_window": 0,
        "inverter_serials_seen": [],
        "relay_params_seen": [],
        "pac_present_count": 0,
        "pac_missing_count": 0,
        "pac_unparseable_count": 0,
        "sample": [],
    }

    if not isinstance(data, list):
        result["discard_reasons"]["response_not_list"] += 1
        return result

    result["sample"] = [_sanitize_sample(item) for item in data[:2]]
    janela_inicio, janela_fim = main._obter_janela_solar_inversor(plant_name)

    for item in data:
        if not isinstance(item, dict):
            result["discard_reasons"]["item_not_dict"] += 1
            continue
        conteudo = item.get("conteudojson")
        if "conteudojson" in item:
            result["has_conteudojson"] = True
        if not isinstance(conteudo, dict):
            result["discard_reasons"]["conteudojson_not_dict"] += 1
            continue
        if "tsleitura" in conteudo:
            result["has_tsleitura"] = True
        try:
            ts = datetime.strptime(conteudo.get("tsleitura", ""), "%Y-%m-%d %H:%M:%S")
        except Exception:
            result["discard_reasons"]["tsleitura_invalid_or_missing"] += 1
            continue

        result["accepted_by_iterar_registros_api_dia"] += 1
        if not (inicio <= ts <= fim):
            result["discard_reasons"]["outside_requested_window"] += 1
            continue
        result["accepted_in_window"] += 1

        if endpoint == "day_inverter":
            inv_id = item.get("idinversor") or conteudo.get("Inversor") or conteudo.get("esn")
            if inv_id and str(inv_id) not in result["inverter_serials_seen"]:
                result["inverter_serials_seen"].append(str(inv_id))
            if not inv_id:
                result["discard_reasons"]["missing_inverter_id"] += 1
            if not (janela_inicio <= ts.time() <= janela_fim):
                result["discard_reasons"]["outside_solar_window"] += 1
            pac_raw = None
            for key in ("Pac", "PAC", "Potencia_Saida", "Pout", "Potencia"):
                if key in conteudo:
                    pac_raw = conteudo.get(key)
                    break
            if pac_raw is None:
                result["pac_missing_count"] += 1
            elif main.extrair_valor_numerico(pac_raw) is None:
                result["pac_unparseable_count"] += 1
            else:
                result["pac_present_count"] += 1

        if endpoint == "day_relay":
            active_params = [p for p in conteudo if p in main.RELAY_PARAMETROS and main._rele_param_ativo(conteudo[p])]
            for param in active_params:
                if param not in result["relay_params_seen"]:
                    result["relay_params_seen"].append(param)

    result["discard_reasons"] = dict(result["discard_reasons"])
    return result


def _production_detector_summary(main, api, endpoint: str, plant_id: str, plant_name: str, inicio: datetime, fim: datetime) -> dict:
    if endpoint == "day_inverter":
        janela_inicio, janela_fim = main._obter_janela_solar_inversor(plant_name)
        falhas, recuperados, tem_dados, falhas_ativas, teve_timeout, max_ts = main.detectar_falhas_inversores(
            api,
            plant_id,
            inicio,
            fim,
            {},
            janela_inicio=janela_inicio,
            janela_fim=janela_fim,
        )
        if teve_timeout:
            motivo = getattr(api, "last_post_day_error_reason", None) or "TIMEOUT_PARCIAL"
        elif not tem_dados:
            motivo = "SEM_DADOS"
        else:
            motivo = "DADOS_VALIDOS"
        return {
            "detector": "detectar_falhas_inversores",
            "tem_dados": tem_dados,
            "teve_timeout_or_api_error": teve_timeout,
            "last_post_day_error_reason": getattr(api, "last_post_day_error_reason", None),
            "falhas_count": len(falhas),
            "recuperados_count": len(recuperados),
            "falhas_ativas_count": len(falhas_ativas),
            "max_ts_processado": max_ts.isoformat() if max_ts else None,
            "motivo_final": motivo,
        }

    alertas, tem_dados, teve_timeout, max_ts = main.detectar_alertas_rele(api, plant_id, inicio, fim)
    if teve_timeout:
        motivo = getattr(api, "last_post_day_error_reason", None) or "TIMEOUT_PARCIAL"
    elif not tem_dados:
        motivo = "SEM_DADOS"
    else:
        motivo = "DADOS_VALIDOS"
    return {
        "detector": "detectar_alertas_rele",
        "tem_dados": tem_dados,
        "teve_timeout_or_api_error": teve_timeout,
        "last_post_day_error_reason": getattr(api, "last_post_day_error_reason", None),
        "alertas_count": len(alertas),
        "alertas_bases": [
            main._chave_evento_rele(plant_id, a.get("rele_id"), a.get("tipo_alerta"), a.get("parametros_chave") or a.get("parametros"))
            for a in alertas[:10]
        ],
        "max_ts_processado": max_ts.isoformat() if max_ts else None,
        "motivo_final": motivo,
    }


def _print_header(title: str) -> None:
    print("\n" + "=" * 80)
    print(title)
    print("=" * 80)


def main_cli() -> int:
    args = _parse_args()
    main = _load_main()

    inicio = _parse_dt(args.date, args.start)
    fim = _parse_dt(args.date, args.end)
    if fim < inicio:
        raise SystemExit("--end precisa ser maior ou igual a --start")

    _print_header("Ambiente")
    for name in ("MONITOR_EMAIL", "MONITOR_PASSWORD", "TEAMS_WEBHOOK_URL", "PVOP_BASE_URL"):
        print(_safe_bool_env(name))
    print(f"PVOP_BASE_URL_EFFECTIVE_PRESENT: {bool(main.PVOP_BASE_URL)}")
    print("Teams: nao sera chamado por este diagnostico")

    _print_header("Login e plantas")
    api = main.PVOperationAPI(email=main.PVOP_EMAIL, password=main.PVOP_PASSWORD, base_url=main.PVOP_BASE_URL)
    print(f"login_success: {bool(api.token)}")
    if not api.token:
        print("ERRO: login falhou ou token ausente. Corrija variaveis/credenciais antes de diagnosticar day_*.")
        return 2

    plants = api.get_plants()
    if plants is None:
        print("ERRO: get_plants retornou None")
        print(f"last_get_plants_timeout: {getattr(api, 'last_get_plants_timeout', None)}")
        print(f"last_get_plants_error: {getattr(api, 'last_get_plants_error', None)}")
        return 3
    print(f"plants_count: {len(plants)}")
    selected = _select_plants(plants, args.plant, args.plant_id, args.max_plants)
    print(f"selected_count: {len(selected)}")
    if not selected:
        print("Nenhuma usina encontrada para os filtros informados.")
        return 4

    endpoints = ["day_inverter", "day_relay"] if args.endpoint == "both" else [args.endpoint]
    date_dt = datetime.strptime(args.date, "%Y-%m-%d")

    for plant in selected:
        plant_id = str(plant.get("id"))
        plant_name = str(plant.get("nome", ""))
        _print_header(f"Usina: {plant_name} | plant_id={plant_id}")
        print(f"janela_consultada_local: {inicio.isoformat(sep=' ')} -> {fim.isoformat(sep=' ')}")
        print(f"horario_local_execucao: {datetime.now().isoformat(sep=' ', timespec='seconds')}")
        for endpoint in endpoints:
            _print_header(f"{endpoint} | {plant_name} | plant_id={plant_id}")
            raw = _call_day_raw(main, api, endpoint, int(plant_id), date_dt)
            safe_raw = {k: v for k, v in raw.items() if k != "json"}
            print(json.dumps(safe_raw, ensure_ascii=False, indent=2, default=str))
            if raw.get("json_valid"):
                analysis = _analyze_records(main, endpoint, raw.get("json"), inicio, fim, plant_name)
                if args.show_sample >= 0 and isinstance(analysis.get("sample"), list):
                    analysis["sample"] = analysis["sample"][: args.show_sample]
                print("analise_parser:")
                print(json.dumps(analysis, ensure_ascii=False, indent=2, default=str))
            else:
                print("analise_parser: indisponivel porque resposta nao e JSON valido")

            detector = _production_detector_summary(main, api, endpoint, plant_id, plant_name, inicio, fim)
            print("resumo_detector_producao:")
            print(json.dumps(detector, ensure_ascii=False, indent=2, default=str))

    return 0


if __name__ == "__main__":
    raise SystemExit(main_cli())
