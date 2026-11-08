import json
from .core import Recorder

_state = {}


def rec():
    if 'r' not in _state:
        from plugins.plugin_storage import plugin_data_dir
        _state['r'] = Recorder(plugin_data_dir('flight-recorder'))
    return _state['r']


def _safe(fn):
    def run(*a, **k):
        try: return fn(*a, **k)
        except Exception: return None   # a recorder must never break the agent
    return run


on_session_start = _safe(lambda **kw: rec().session_start(**kw))
on_pre_llm_call = _safe(lambda user_message=None, **kw: rec().user(user_message, **kw))
on_post_api_request = _safe(lambda **kw: rec().model(**kw))
on_post_tool_call = _safe(lambda tool_name='', args=None, result='', **kw: rec().tool(tool_name, args or {}, result, **kw))
on_post_llm_call = _safe(lambda assistant_response=None, **kw: rec().final(assistant_response, **kw))


def invoke(name, args):
    try:
        r = rec()
        if name == 'flight_list': return json.dumps(r.list())
        if name == 'flight_summary': return json.dumps(r.analyze(args['session_id']))
        if name == 'flight_export': return json.dumps(r.export(args['session_id']))
        return json.dumps(r.fork_brief(args['session_id'], args['step']))
    except (ValueError, TypeError, OSError, KeyError) as exc:
        return json.dumps({'error': str(exc)})


S = {'type': 'string'}
TOOLS = {
    'flight_list': ('List recorded sessions with event, tool-call and failure counts.', {}, []),
    'flight_summary': ('Analyze a recorded session: counts, tokens, time, per-tool failures and markers for the first failure, retries, loops and long waits.', {'session_id': S}, ['session_id']),
    'flight_export': ('Write a self-contained HTML timeline of a session (scrub bar, filters, search, markers). No network access; secrets are redacted by pattern.', {'session_id': S}, ['session_id']),
    'flight_fork_brief': ('Write a text brief of a session up to a chosen step, to start a new session from that point. Recorded text only, not a state restore.', {'session_id': S, 'step': {'type': 'integer', 'minimum': 0}}, ['session_id', 'step']),
}


def register(ctx):
    for hook, fn in (('on_session_start', on_session_start), ('pre_llm_call', on_pre_llm_call), ('post_api_request', on_post_api_request), ('post_tool_call', on_post_tool_call), ('post_llm_call', on_post_llm_call)):
        ctx.register_hook(hook, fn)
    for name, (description, properties, required) in TOOLS.items():
        ctx.register_tool(name=name, toolset='flight_recorder', schema={'name': name, 'description': description,
            'parameters': {'type': 'object', 'properties': properties, 'required': required, 'additionalProperties': False}},
            handler=lambda args, _name=name, **kwargs: invoke(_name, args))
