"""Generate Android/Windows projections from the pinned service-routing contract.

Run with --check in validation. Updating the contract is a separate reviewed
step: preserve input commit/hash provenance, ad exclusions and shared-CDN bounds.
"""
import argparse
import json
import re
from pathlib import Path

root = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser()
parser.add_argument('--check', action='store_true')
args = parser.parse_args()
contract = json.loads((root / 'routing-policy/service-routing-v1.json').read_text(encoding='utf-8'))
assert contract['format'] == 'BIFROST-SERVICE-ROUTING-1'
youtube = json.loads((root / 'routing-policy/youtube-playback-v1.json').read_text(encoding='utf-8'))
assert youtube['format'] == 'BIFROST-YOUTUBE-PLAYBACK-1'
suffixes, domains = contract['domain_suffix'], contract['domain']
for values in (suffixes, domains, youtube['domain_suffix'], youtube['domain'], youtube['android_packages']):
    assert values == sorted(set(values))
    assert all(re.fullmatch(r'(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z][a-z0-9-]*', d) for d in values)

def kotlin(name, values):
    chunks = ['\\n'.join(values[i:i+400]) for i in range(0, len(values), 400)]
    expression = ('listOf(' + ',\n        '.join(json.dumps(s) for s in chunks)
                  + ').flatMap { it.split("\\\\n") }.filter(String::isNotBlank)') if chunks else 'emptyList()'
    return f'    val {name}: List<String> = {expression}\n'

def cs(name, values):
    return f'    internal static readonly string[] {name} = [\n' + ''.join(f'        {json.dumps(v)},\n' for v in values) + '    ];\n'

outputs = {
    'android-app/src/main/java/com/bifrost/client/BifrostServiceRouting.kt':
        'package com.bifrost.client\n\n/** Generated from routing-policy/service-routing-v1.json; see provenance there. */\ninternal object BifrostServiceRouting {\n'
        + kotlin('suffixes', suffixes) + kotlin('domains', domains)
        + kotlin('youtubeSuffixes', youtube['domain_suffix']) + kotlin('youtubeDomains', youtube['domain'])
        + kotlin('youtubePackages', youtube['android_packages'])
        + f'    const val youtubeUdpIdleTimeout = {json.dumps(youtube["udp_idle_timeout"])}\n' + '}\n',
    'windows-service/BifrostServiceRouting.cs':
        'namespace Bifrost.ClientService;\n\n// Generated from routing-policy/service-routing-v1.json; factual domains only.\ninternal static class BifrostServiceRouting\n{\n'
        + cs('Suffixes', suffixes) + cs('Domains', domains)
        + cs('YoutubeSuffixes', youtube['domain_suffix']) + cs('YoutubeDomains', youtube['domain']) + '}\n',
}
for relative, content in outputs.items():
    path = root / relative
    if args.check:
        if path.read_text(encoding='utf-8') != content:
            raise SystemExit(f'Routing projection differs: {relative}')
    else:
        path.write_text(content, encoding='utf-8')
print(f'Service routing projections match: {len(suffixes)} suffixes + {len(domains)} exact domains')
