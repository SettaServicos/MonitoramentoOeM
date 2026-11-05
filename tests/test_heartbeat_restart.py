from datetime import datetime

import pytest

import main


@pytest.fixture
def service(tmp_path, monkeypatch):
    monkeypatch.setattr(main, 'STATE_FILE', tmp_path / 'state.json')
    svc = main.MonitorService(object())
    monkeypatch.setattr(svc, 'executar_varredura_rele', lambda: None)
    monkeypatch.setattr(svc, 'executar_varredura_inversor', lambda: None)
    return svc


@pytest.mark.parametrize('now, expected', [
    (datetime(2026, 11, 4, 12, 0, 1), datetime(2026, 11, 4, 12)),
    (datetime(2026, 11, 4, 16), datetime(2026, 11, 4, 12)),
    (datetime(2026, 11, 4, 12), datetime(2026, 11, 4, 12)),
    (datetime(2026, 11, 4, 6), datetime(2026, 11, 3, 23)),
])
def test_restart_recovers_latest_due_slot(service, now, expected):
    assert service._horario_heartbeat_pendente(now) == expected


def test_success_survives_restart_and_is_not_repeated(service, monkeypatch):
    slot = datetime(2026, 11, 4, 12)
    monkeypatch.setattr(main, '_teams_post_card', lambda **kw: True)
    assert service._enviar_heartbeat(slot) is True
    restarted = main.MonitorService(object())
    restarted._load_state()
    assert restarted.ultimo_heartbeat_enviado == slot
    assert restarted._horario_heartbeat_pendente(datetime(2026, 11, 4, 12, 0, 1)) is None
    assert restarted._horario_heartbeat_pendente(datetime(2026, 11, 4, 17)) == datetime(2026, 11, 4, 17)


def test_failed_delivery_does_not_advance_checkpoint(service, monkeypatch):
    previous = datetime(2026, 11, 4, 7)
    service.ultimo_heartbeat_enviado = previous
    monkeypatch.setattr(main, '_teams_post_card', lambda **kw: False)
    assert service._enviar_heartbeat(datetime(2026, 11, 4, 12)) is False
    assert service.ultimo_heartbeat_enviado == previous
    assert service._horario_heartbeat_pendente(datetime(2026, 11, 4, 12, 1)) == datetime(2026, 11, 4, 12)


def test_legacy_state_without_checkpoint_is_supported(service):
    import json
    service._save_state()
    saved = json.loads(main.STATE_FILE.read_text(encoding='utf-8'))
    saved.pop('ultimo_heartbeat_enviado')
    main.STATE_FILE.write_text(json.dumps(saved), encoding='utf-8')
    service._load_state()
    assert service.ultimo_heartbeat_enviado is None
    assert service._horario_heartbeat_pendente(datetime(2026, 11, 4, 12, 0, 1)) == datetime(2026, 11, 4, 12)


def test_loop_waits_for_next_slot_after_success(service, monkeypatch):
    class Clock(datetime):
        @classmethod
        def now(cls):
            return cls(2026, 11, 4, 12, 0, 1)
    monkeypatch.setattr(main, 'datetime', Clock)
    sends = []
    waits = []
    monkeypatch.setattr(main, '_teams_post_card', lambda **kw: sends.append(kw) or True)
    def wait(seconds):
        waits.append(seconds)
        service.stop_event.set()
        return True
    monkeypatch.setattr(service.stop_event, 'wait', wait)
    service._loop_heartbeat()
    assert len(sends) == 1
    assert waits == [5 * 3600 - 1]


def test_loop_retries_failed_slot_without_busy_loop(service, monkeypatch):
    class Clock(datetime):
        @classmethod
        def now(cls):
            return cls(2026, 11, 4, 12, 0, 1)
    monkeypatch.setattr(main, 'datetime', Clock)
    waits = []
    calls = []
    def send(slot):
        calls.append(slot)
        if len(calls) == 2:
            service.stop_event.set()
            return True
        return False
    monkeypatch.setattr(service, '_enviar_heartbeat', send)
    monkeypatch.setattr(service.stop_event, 'wait', lambda seconds: waits.append(seconds) or False)
    service._loop_heartbeat()
    assert calls == [datetime(2026, 11, 4, 12)] * 2
    assert waits == [60]


def test_text_distinguishes_fresh_stale_missing_and_recovery(service, monkeypatch):
    class Clock(datetime):
        @classmethod
        def now(cls):
            return cls(2026, 11, 4, 12)
    monkeypatch.setattr(main, 'datetime', Clock)
    for serial, pac, ts in [
        ('FRESH', 0, '2026-11-04T11:55:00'),
        ('STALE', 0, '2026-11-03T17:00:00'),
        ('MISSING', None, None),
        ('RECOVERY', 100, '2026-11-04T11:55:00'),
    ]:
        service.estado_inversores['1:' + serial] = {
            'ativa': True, 'ultima_leitura_pac': pac, 'ultima_leitura_ts': ts,
            'alerta': {'usina': 'Usina 1', 'inversor': serial}}
    payload = {}
    def send(**kwargs):
        payload.update(kwargs)
        return True
    monkeypatch.setattr(main, '_teams_post_card', send)
    service._enviar_heartbeat(Clock(2026, 11, 4, 12))
    text = payload['text']
    assert 'Falhas de inversor confirmadas: 2' in text
    assert 'Falhas anteriores sem dados recentes: 2' in text
    assert 'Recuperação em confirmação' in text
    assert text.index('Série: FRESH') < text.index('Falhas anteriores sem dados recentes: 2')
    assert text.index('Série: STALE') > text.index('Falhas anteriores sem dados recentes: 2')
    assert 'Status: OK' not in text
    assert all(s['ativa'] for s in service.estado_inversores.values())


@pytest.mark.parametrize('reading,now,name,expected', [
    ('2026-11-03T17:00:00', '2026-11-03T23:00:00', 'Usina', True),
    ('2026-11-03T17:00:00', '2026-11-04T06:20:00', 'Usina', True),
    ('2026-11-03T17:00:00', '2026-11-04T07:00:00', 'Usina', True),
    ('2026-11-03T17:00:00', '2026-11-04T07:00:01', 'Usina', False),
    ('2026-11-03T16:00:00', '2026-11-03T23:00:00', 'Usina', False),
    ('2026-11-02T17:00:00', '2026-11-04T06:00:00', 'Usina', False),
    ('2026-11-03T17:00:00', '2026-11-04T07:45:00', 'COMP.IBI.2500.LT01', True),
    ('2026-11-03T17:00:00', '2026-11-04T08:00:01', 'COMP.IBI.2500.LT01', False),
    ('2026-11-04T12:05:00', '2026-11-04T12:00:00', 'Usina', False),
])
def test_solar_freshness(reading, now, name, expected):
    state = {'ativa': True, 'ultima_leitura_pac': 0, 'ultima_leitura_ts': reading,
             'alerta': {'usina': name}}
    assert main.MonitorService._inversor_conta_no_heartbeat(state, datetime.fromisoformat(now)) is expected
