from datetime import datetime, timedelta, time
import threading

import pytest
import main


class API:
    last_get_plants_error = False
    last_get_plants_timeout = False
    last_post_day_error = False

    def __init__(self, records=(), failed=()):
        self.records = list(records)
        self.failed = set(failed)

    def get_plants(self):
        return [{"id": 1, "nome": "Usina teste"}]

    def post_day(self, endpoint, plant_id, day):
        if day.date() in self.failed:
            return None, True
        return [r for r in self.records if r['conteudojson']['tsleitura'].startswith(str(day.date()))], False


def reading(hour, minute, pac, day=4):
    return {'idinversor': 'I1', 'conteudojson': {
        'tsleitura': f'2026-11-{day:02} {hour:02}:{minute:02}:00', 'Pac': pac}}


def active():
    return {'ativa': True, 'notificado': False, 'rec_seq': 0, 'seq_zero': 6,
            'ultima_leitura_ts': '2026-11-04T16:55:00', 'ultima_leitura_pac': 0,
            'ultima_confirmacao_ts': '2026-11-04T16:55:00',
            'alerta': {'usina': 'Usina teste', 'inversor': 'I1', 'ts_iso': '2026-11-04T16:17:00',
                       'status': 'FALHA', 'horario': '04/11/2026 16:17:00',
                       'indicadores': {'pac': 0}, 'capacidade': 100}}


def detect(records, previous=None, failed=(), start=None, end=None, **kwargs):
    return main.detectar_falhas_inversores(
        API(records, failed), '1', start or datetime(2026, 11, 4),
        end or datetime(2026, 11, 4, 23), previous or {}, revalidar=True, **kwargs)


@pytest.fixture
def service(tmp_path, monkeypatch):
    monkeypatch.setattr(main, 'STATE_FILE', tmp_path / 'state.json')
    monkeypatch.setattr(main, 'RELE_PLANT_IDS', {'1'})
    class Clock(datetime):
        @classmethod
        def now(cls):
            return cls(2026, 11, 4, 18)
    monkeypatch.setattr(main, 'datetime', Clock)
    return main.MonitorService(API())


def test_concurrent_scans_do_not_duplicate_successful_notification(service, monkeypatch):
    service.estado_inversores['1:I1'] = active()
    sending, release, second_started, second_sent = [threading.Event() for _ in range(4)]
    calls, errors = [], []
    def send(alert):
        calls.append(alert)
        if len(calls) == 1:
            sending.set()
            assert release.wait(3)
        else:
            second_sent.set()
        return True
    monkeypatch.setattr(service, '_notificar_inversor', send)
    def scan(second=False):
        try:
            if second:
                second_started.set()
            service.executar_varredura_inversor()
        except BaseException as exc:
            errors.append(exc)
    first = threading.Thread(target=scan)
    second = threading.Thread(target=scan, args=(True,))
    try:
        first.start()
        assert sending.wait(2)
        second.start()
        assert second_started.wait(2)
        second_sent.wait(.2)
    finally:
        release.set()
        first.join(3)
        if second.ident:
            second.join(3)
    assert not first.is_alive() and not second.is_alive()
    assert not errors
    assert len(calls) == 1
    assert service.estado_inversores['1:I1']['notificado']


def test_failed_notification_can_be_retried(service, monkeypatch):
    service.estado_inversores['1:I1'] = active()
    monkeypatch.setattr(service, '_notificar_inversor', lambda alert: False)
    service.executar_varredura_inversor()
    assert not service.estado_inversores['1:I1']['notificado']
    monkeypatch.setattr(service, '_notificar_inversor', lambda alert: True)
    service.executar_varredura_inversor()
    assert service.estado_inversores['1:I1']['notificado']


def relay(ts, fault=False):
    return {'idrele': 'R1', 'conteudojson': {'tsleitura': ts, 'r27A': fault}}


def test_relay_checkpoint_follows_sample_and_finds_delayed_reading(service):
    service.api_rele.records = [relay('2026-11-04 16:10:00')]
    service.executar_varredura_rele()
    assert service.ultima_varredura_rele_por_usina['1'] == datetime(2026, 11, 4, 16, 10)
    service.executar_varredura_rele()
    assert service.ultima_varredura_rele_por_usina['1'] == datetime(2026, 11, 4, 16, 10)
    service.api_rele.records.append(relay('2026-11-04 16:17:00', True))
    service.executar_varredura_rele()
    assert service.rele_alertas_ativos
    assert service.ultima_varredura_rele_por_usina['1'] == datetime(2026, 11, 4, 16, 17)


def test_two_evening_positives_recover_existing_fault():
    result = detect([reading(17, 5, 1.3), reading(17, 10, .61)], {'1:I1': active()})
    assert len(result[1]) == 1
    assert result[1][0]['ts_leitura'] == datetime(2026, 11, 4, 17, 10)
    assert not result[3]['1:I1']['ativa']


@pytest.mark.parametrize('values', [[1], [1, 0, 1], [1, float('nan')], [1, float('inf')]])
def test_evening_recovery_requires_two_valid_consecutive_positives(values):
    result = detect([reading(17, 5 + i*5, p) for i, p in enumerate(values)], {'1:I1': active()})
    assert not result[1]
    assert result[3].get('1:I1', active())['ativa']


def test_night_zeros_do_not_open_fault():
    result = detect([reading(18, i*5, 0) for i in range(6)])
    assert not result[0]
    assert not any(s['ativa'] for s in result[3].values())


def test_next_morning_requires_six_new_zeros_after_evening_recovery():
    records = [reading(17, 5, 1), reading(17, 10, 1)]
    records += [reading(18, i*5, 0) for i in range(6)]
    records += [reading(6, 30+i*5, 0, day=5) for i in range(5)]
    result = detect(records, {'1:I1': active()}, end=datetime(2026, 11, 5, 7))
    assert len(result[1]) == 1
    assert not result[0]
    assert not result[3]['1:I1']['ativa']
    records.append(reading(6, 55, 0, day=5))
    result = detect(records, {'1:I1': active()}, end=datetime(2026, 11, 5, 7))
    assert len(result[0]) == 1
    assert result[0][0]['ts_leitura'] == datetime(2026, 11, 5, 6, 55)


def test_counter_does_not_cross_date_even_without_night_samples():
    previous = {'1:I1': {**active(), 'ativa': False, 'seq_zero': 5}}
    result = detect([reading(6, 30, 0, day=5)], previous, end=datetime(2026, 11, 5, 7))
    assert not result[0]
    assert result[3]['1:I1']['seq_zero'] == 1


def test_evening_recovery_survives_restart_without_recounting(service):
    service.estado_inversores['1:I1'] = active()
    service.api_inversor.records = [reading(17, 5, 1)] * 3
    service.executar_varredura_inversor()
    assert service.estado_inversores['1:I1']['rec_seq'] == 1
    restarted = main.MonitorService(service.api_inversor)
    restarted._load_state()
    restarted.executar_varredura_inversor()
    assert restarted.estado_inversores['1:I1']['ativa']
    restarted.api_inversor.records.append(reading(17, 10, 1))
    restarted.executar_varredura_inversor()
    assert not restarted.estado_inversores['1:I1']['ativa']


def test_custom_solar_window_does_not_open_early_fault():
    result = detect([reading(6, 30+i*5, 0) for i in range(6)], janela_inicio=time(7, 30))
    assert not result[0]


def test_history_timeout_does_not_block_complete_current_fault():
    result = detect([reading(10, i*5, 0) for i in range(6)],
                    failed={datetime(2026, 11, 3).date()}, start=datetime(2026, 11, 3))
    assert len(result[0]) == 1
    assert result[4] is False


def test_history_timeout_resets_carried_counter():
    previous = {'1:I1': {**active(), 'ativa': False, 'seq_zero': 5,
                        'ultima_leitura_ts': '2026-11-02T16:55:00'}}
    result = detect([reading(10, 0, 0)], previous,
                    failed={datetime(2026, 11, 3).date()}, start=datetime(2026, 11, 3))
    assert not result[0]
    assert result[3]['1:I1']['seq_zero'] == 1


def test_current_day_timeout_preserves_existing_state(service):
    service.estado_inversores['1:I1'] = active()
    service.api_inversor.failed = {datetime(2026, 11, 4).date()}
    service.api_inversor.records = [reading(17, 5, 1), reading(17, 10, 1)]
    service.executar_varredura_inversor()
    assert service.estado_inversores['1:I1'] == active()


def test_history_timeout_allows_current_confirmed_recovery(service):
    service.estado_inversores['1:I1'] = active()
    service.api_inversor.failed = {datetime(2026, 11, 3).date()}
    service.api_inversor.records = [reading(17, 5, 1), reading(17, 10, 1)]
    service.executar_varredura_inversor()
    assert not service.estado_inversores['1:I1']['ativa']


@pytest.mark.parametrize('invalid', [None, float('nan'), float('inf'), 'invalid'])
def test_invalid_sample_interrupts_recovery(invalid):
    result = detect([reading(17, 5, 1), reading(17, 10, invalid), reading(17, 15, 1)],
                    {'1:I1': active()})
    assert not result[1]
    assert result[3]['1:I1']['rec_seq'] == 1


def test_evening_zero_preserves_recent_solar_confirmation_in_heartbeat():
    result = detect([reading(17, 5, 0)], {'1:I1': active()})
    state = result[3]['1:I1']
    assert state['ultima_confirmacao_ts'] == '2026-11-04T16:55:00'
    assert main.MonitorService._inversor_conta_no_heartbeat(state, datetime(2026, 11, 4, 23))
    assert not main.MonitorService._inversor_conta_no_heartbeat(state, datetime(2026, 11, 5, 12))


def test_evening_positive_shows_recovery_pending_in_heartbeat():
    result = detect([reading(17, 5, 1)], {'1:I1': active()})
    assert main.MonitorService._inversor_conta_no_heartbeat(result[3]['1:I1'], datetime(2026, 11, 4, 18))


def test_relay_first_empty_scan_does_not_hide_late_data(service):
    service.executar_varredura_rele()
    assert '1' not in service.ultima_varredura_rele_por_usina
    service.api_rele.records = [relay('2026-11-04 16:17:00', True)]
    service.executar_varredura_rele()
    assert service.rele_alertas_ativos


def test_operation_lock_is_released_after_send_exception(service, monkeypatch):
    service.estado_inversores['1:I1'] = active()
    def fail(alert):
        raise RuntimeError('send failed')
    monkeypatch.setattr(service, '_notificar_inversor', fail)
    with pytest.raises(RuntimeError, match='send failed'):
        service.executar_varredura_inversor()
    monkeypatch.setattr(service, '_notificar_inversor', lambda alert: True)
    worker = threading.Thread(target=service.executar_varredura_inversor, daemon=True)
    worker.start()
    worker.join(2)
    assert not worker.is_alive()
    assert service.estado_inversores['1:I1']['notificado']


def test_recovery_closes_incident_at_sample_time(service):
    service.estado_inversores['1:I1'] = active()
    service._registrar_inicio_incidente_inversor('1:I1', '1', 'Usina teste', 'I1', main.datetime(2026, 11, 4, 16, 17))
    service.api_inversor.records = [reading(17, 5, 1), reading(17, 10, 1)]
    service.executar_varredura_inversor()
    service.executar_varredura_inversor()
    assert '1:I1' not in service.incidentes_inv_ativos
    assert len(service.historico_incidentes) == 1
    assert service.historico_incidentes[0]['fim_ts'] == '2026-11-04T17:10:00'


def test_error_response_with_records_never_recovers(service, monkeypatch):
    service.estado_inversores['1:I1'] = active()
    monkeypatch.setattr(service.api_inversor, 'post_day', lambda *args: (
        [reading(17, 5, 1), reading(17, 10, 1)], True))
    service.executar_varredura_inversor()
    assert service.estado_inversores['1:I1'] == active()


@pytest.mark.parametrize('invalid', [None, float('nan'), 'invalid'])
def test_invalid_sample_does_not_delay_failure_opening(invalid):
    # Leitura invalida e neutra para a abertura: nao soma nem zera a contagem de zeros.
    zeros = [reading(10, i * 5, 0) for i in range(3)]
    tail = [reading(10, 20 + i * 5, 0) for i in range(3)]
    result = detect(zeros + [reading(10, 17, invalid)] + tail)
    assert len(result[0]) == 1
    assert result[0][0]['ts_leitura'] == datetime(2026, 11, 4, 10, 30)


def test_failed_day_keeps_earlier_days_in_weekly_history():
    # Relatorio semanal: um dia com erro da API nao pode apagar incidentes de dias anteriores.
    records = [reading(10, i * 5, 0, day=2) for i in range(6)] + \
              [reading(11, i * 5, 5, day=2) for i in range(2)]
    falhas, recuperados, *_ = main.detectar_falhas_inversores(
        API(records, failed={datetime(2026, 11, 3).date()}), '1',
        datetime(2026, 11, 1), datetime(2026, 11, 4, 23), {})
    assert [f['ts_leitura'] for f in falhas] == [datetime(2026, 11, 2, 10, 25)]
    assert [r['ts_leitura'] for r in recuperados] == [datetime(2026, 11, 2, 11, 5)]


def test_scan_inversor_consulta_um_unico_dia(service):
    service.ultima_varredura_inversor_por_usina['1'] = datetime(2026, 11, 3, 16, 50)
    calls = []
    original = service.api_inversor.post_day
    service.api_inversor.post_day = lambda ep, pid, day: calls.append(day.date()) or original(ep, pid, day)
    service.executar_varredura_inversor()
    assert calls == [datetime(2026, 11, 4).date()]
