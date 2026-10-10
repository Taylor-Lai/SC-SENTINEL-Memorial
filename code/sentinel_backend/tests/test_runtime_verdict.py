import asyncio
import uuid
from types import SimpleNamespace

from app.models.vulnerability import VerifyStatus
from app.worker import fuzzing_task


class _Rows:
    def __init__(self, items):
        self.items = items

    def scalars(self):
        return self

    def all(self):
        return self.items


class _Session:
    def __init__(self, items):
        self.items = items
        self.events = []
        self.committed = False

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_):
        pass

    async def execute(self, *_):
        return _Rows(self.items)

    def add(self, item):
        self.events.append(item)

    async def commit(self):
        self.committed = True


def _finding(vuln_type):
    return SimpleNamespace(
        id=uuid.uuid4(), vuln_type=vuln_type,
        verify_status=VerifyStatus.UNVERIFIED, llm_original_type=None,
        ebpf_corrected=False, afl_log=None,
    )


def test_strong_event_corrects_and_confirms_without_crash(monkeypatch):
    corrected = _finding('buffer_overflow')
    weak = _finding('use_after_free')
    untriggered = _finding('use_after_free')
    session = _Session([corrected, weak, untriggered])
    monkeypatch.setattr(fuzzing_task, 'AsyncSessionLocal', lambda: session)
    sandbox = SimpleNamespace(package_results=[
        {'vuln_id': str(corrected.id), 'crash_found': False,
         'ebpf_events': [{'event': 'double_free'}]},
        {'vuln_id': str(weak.id), 'crash_found': False,
         'ebpf_events': [{'event': 'possible_buffer_overflow'}]},
        {'vuln_id': str(untriggered.id), 'crash_found': False, 'ebpf_events': []},
    ])

    asyncio.run(fuzzing_task._save_fuzzing_results(str(uuid.uuid4()), sandbox))

    assert corrected.vuln_type == 'double_free'
    assert corrected.llm_original_type == 'buffer_overflow'
    assert corrected.ebpf_corrected is True
    assert corrected.verify_status == VerifyStatus.CONFIRMED
    assert weak.verify_status == VerifyStatus.UNVERIFIED
    assert untriggered.verify_status == VerifyStatus.NOT_REPRODUCED
    assert session.committed and len(session.events) == 2
