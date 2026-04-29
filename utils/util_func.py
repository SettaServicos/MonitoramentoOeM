from datetime import datetime, timedelta, time
from re import search
from typing import Any, Optional


# Normaliza valores numericos vindos como string ou numero bruto para float.
def extrair_valor_numerico(valor: Any) -> Optional[float]:
    if isinstance(valor, bool):
        return float(valor)
    if isinstance(valor, (int, float)):
        return float(valor)
    if isinstance(valor, str):
        txt = valor.strip()
        if "," in txt and "." in txt and txt.rfind(",") > txt.rfind("."):
            txt = txt.replace(".", "").replace(",", ".")
        elif "," in txt and "." not in txt:
            txt = txt.replace(",", ".")
        m = search(r"([-+]?\d*\.\d+|\d+)", txt)
        if m:
            try:
                return float(m.group(1))
            except Exception:
                return None
    return None


def parse_iso_datetime(valor: Any) -> Optional[datetime]:
    if not valor:
        return None
    try:
        return datetime.fromisoformat(str(valor))
    except Exception:
        return None


def formatar_duracao(segundos: float) -> str:
    secs = max(0, int(round(float(segundos))))
    h, rem = divmod(secs, 3600)
    m, s = divmod(rem, 60)
    return f"{h:02d}:{m:02d}:{s:02d}"


def formatar_janela_solar_label(janela_inicio: time, janela_fim: time) -> str:
    return f"{janela_inicio.strftime('%H:%M')}-{janela_fim.strftime('%H:%M')}"


def inicio_semana(dt_ref: datetime) -> datetime:
    return datetime.combine(dt_ref.date() - timedelta(days=dt_ref.weekday()), datetime.min.time())


def is_placeholder(value: str) -> bool:
    if value is None:
        return True
    raw = str(value).strip()
    return (not raw) or (raw.upper() == "COLE_AQUI")


def calcular_sobreposicao_segundos(inicio: datetime, fim: datetime, faixa_ini: datetime, faixa_fim: datetime) -> float:
    ini = max(inicio, faixa_ini)
    end = min(fim, faixa_fim)
    if end <= ini:
        return 0.0
    return float((end - ini).total_seconds())


def fmt_ts(valor: Any) -> str:
    if isinstance(valor, datetime):
        return valor.strftime("%d/%m/%Y %H:%M:%S")
    return ""


def intervalos_se_sobrepoem(inicio_a: Any, fim_a: Any, inicio_b: Any, fim_b: Any) -> bool:
    return inicio_a <= fim_b and inicio_b <= fim_a


def valor_rele_ativo_relatorio(valor: Any) -> bool:
    if isinstance(valor, bool):
        return valor
    if isinstance(valor, (int, float)):
        return valor == 1
    if isinstance(valor, str):
        txt = valor.strip().lower()
        if txt in {"true", "1"}:
            return True
        try:
            return float(txt) == 1.0
        except Exception:
            return False
    return False


# Formata intervalo de tempo das leituras para texto amigavel.
def formatar_intervalo_alerta(ts_first: Optional[datetime], ts_last: Optional[datetime]) -> str:
    if not ts_first or not ts_last:
        return ""
    if ts_first == ts_last:
        return f"Alerta às {ts_first.strftime('%H:%M')}"
    return f"Primeiro alerta às {ts_first.strftime('%H:%M')} e último às {ts_last.strftime('%H:%M')}"
