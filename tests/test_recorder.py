import importlib.util
import json
from pathlib import Path
import re
import sys
import tempfile
import unittest

root = Path(__file__).parents[1]
spec = importlib.util.spec_from_file_location('flight_fixture', root / '__init__.py', submodule_search_locations=[str(root)])
module = importlib.util.module_from_spec(spec); sys.modules[spec.name] = module; spec.loader.exec_module(module)
core = sys.modules['flight_fixture.core']
OKR, BAD = json.dumps({'output': 'ok', 'exit_code': 0}), json.dumps({'output': 'boom', 'exit_code': 1})


class Clock:
    def __init__(self): self.t = 1000.0
    def __call__(self): self.t += 2.0; return self.t


class RecorderTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.clock = Clock(); self.r = core.Recorder(self.tmp.name, clock=self.clock)

    def tearDown(self): self.tmp.cleanup()

    def tool(self, tool, args, result, **kw): self.r.tool(tool, args, result, session_id='s1', duration_ms=120, **kw)

    def session(self):
        self.r.session_start(session_id='s1', model='m', platform='cli'); self.r.user('Fix the failing test', session_id='s1')
        self.r.model(session_id='s1', model='m', provider='p', api_duration=1.5, usage={'input_tokens': 100, 'output_tokens': 20}, finish_reason='tool_calls', assistant_tool_call_count=1, assistant_message={'content': 'Let me run the tests'})
        self.tool('terminal', {'command': 'pytest'}, BAD); self.tool('terminal', {'command': 'pytest'}, BAD); self.tool('terminal', {'command': 'pytest'}, BAD)
        self.tool('write_file', {'path': 'a.py'}, json.dumps({'verified': True})); self.r.final('Fixed.', session_id='s1')

    def test_records_every_kind_and_summarizes_tokens_and_failures(self):
        self.session(); a = self.r.analyze('s1')
        self.assertEqual((a['model_calls'], a['tool_calls'], a['failures'], a['input_tokens'], a['output_tokens']), (1, 4, 3, 100, 20))
        self.assertEqual(a['tools']['terminal'], {'calls': 3, 'failures': 3, 'ms': 360})

    def test_markers_find_first_failure_retries_and_a_loop(self):
        self.session(); types = {m['type'] for m in self.r.analyze('s1')['markers']}
        self.assertTrue({'first_failure', 'loop', 'retry'} <= types)

    def test_secrets_are_redacted_before_they_are_written(self):
        key = 'sk-' + 'a1B2c3D4' * 4
        self.tool('terminal', {'command': f'curl -H "Authorization: Bearer {key}" x'}, json.dumps({'output': f'token={key} ghp_' + 'Z' * 30}))
        raw = (Path(self.tmp.name) / 'sessions' / 's1.jsonl').read_text(); self.assertNotIn(key, raw); self.assertNotIn('ghp_' + 'Z' * 30, raw); self.assertIn('[redacted]', raw)

    def test_export_is_one_self_contained_page_and_cannot_be_injected(self):
        evil = '</script><script>document.title="pwned"</script><img src=x onerror=alert(1)>'
        self.tool('terminal', {'command': 'echo'}, json.dumps({'output': evil, 'exit_code': 0}))
        out = self.r.export('s1'); page = Path(out['path']).read_text()
        self.assertEqual(page.count('<script'), 2); self.assertNotIn('</script><script>document', page); self.assertNotIn('<img src=x', page)
        self.assertIn("default-src 'none'", page); self.assertNotRegex(page, r'(src|href)=["\']https?://')
        self.assertEqual(oct(Path(out['path']).stat().st_mode & 0o777), '0o600')

    def test_embedded_data_round_trips(self):
        self.session(); page = Path(self.r.export('s1')['path']).read_text()
        raw = re.search(r'<script id="d" type="application/json">(.*?)</script>', page, re.S).group(1); data = json.loads(raw)
        self.assertEqual(len(data['events']), 8); self.assertEqual(data['info']['failures'], 3)

    def test_fork_brief_includes_only_history_to_the_step(self):
        self.session(); b = self.r.fork_brief('s1', 3)['brief']; self.assertIn('Fix the failing test', b); self.assertIn('FAILED', b); self.assertNotIn('Fixed.', b)
        with self.assertRaises(ValueError): self.r.fork_brief('s1', 99)

    def test_validation_list_and_hooks_never_raise(self):
        module._state['r'] = self.r; self.addCleanup(module._state.clear)
        self.session(); self.assertEqual(self.r.list()['sessions'][0]['failures'], 3)
        for bad in ('../x', '', 'a/b'):
            with self.assertRaises(ValueError): self.r.file(bad)
        with self.assertRaises(ValueError): self.r.events('nope')
        self.assertIsNone(module.on_post_tool_call(tool_name='x', args=None, result=None, session_id='../bad'))
        self.assertIsNone(module.on_post_api_request(usage='not a dict'))

    def test_hook_registration(self):
        seen = {}
        class Ctx:
            def register_hook(self, n, cb): seen[n] = cb
            def register_tool(self, **kw): seen.setdefault('t', []).append(kw['name'])
        module.register(Ctx()); self.assertEqual(sorted(k for k in seen if k != 't'), ['on_session_start', 'post_api_request', 'post_llm_call', 'post_tool_call', 'pre_llm_call'])


if __name__ == '__main__': unittest.main()
