"""Export the exact Windows pinned geodata to sing-box source rule sets.

Usage: python export-android-routing.py GEODATA_DIRECTORY
maxminddb is used to regenerate GeoIP.  If it is unavailable, an existing
GeoIP output is accepted only when its previous manifest is from the exact
same pinned source commit and its bytes/hash still match that manifest.
No network access or runtime download is required.
"""
import hashlib
import json
import sys
from pathlib import Path
try:
    import maxminddb
except ModuleNotFoundError:
    maxminddb = None

root = Path(__file__).resolve().parents[1]
lock = json.loads((root / 'core-adapters/mihomo-geodata.lock.json').read_text())
source = Path(sys.argv[1])
out = root / 'android-app/src/main/assets/routing'
out.mkdir(parents=True, exist_ok=True)
previous_manifest_path = out / 'manifest.json'
previous_manifest = json.loads(previous_manifest_path.read_text()) if previous_manifest_path.exists() else None
for asset in lock['assets']:
    data = (source / asset['file']).read_bytes()
    assert len(data) == asset['bytes'] and hashlib.sha256(data).hexdigest() == asset['sha256'], 'pinned geodata mismatch'

def varint(data, pos):
    result = shift = 0
    while True:
        value = data[pos]; pos += 1
        result |= (value & 127) << shift
        if value < 128: return result, pos
        shift += 7
        assert shift < 64

def fields(data):
    pos = 0
    while pos < len(data):
        key, pos = varint(data, pos)
        if key & 7 == 0:
            value, pos = varint(data, pos)
        elif key & 7 == 2:
            size, pos = varint(data, pos)
            value = data[pos:pos + size]; pos += size
        else: raise ValueError('unsupported protobuf wire type')
        yield key >> 3, value

manifest = {'format': 'BIFROST-ANDROID-ROUTING-1', 'source_commit': lock['commit'],
            'source_assets': lock['assets'], 'files': []}
def save(name, rule):
    data = (json.dumps({'version': 3, 'rules': [rule]}, ensure_ascii=False, separators=(',', ':')) + '\n').encode()
    (out / (name + '.json')).write_bytes(data)
    manifest['files'].append({'name': name + '.json', 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()})

categories = {
    'cn': ('cn', None),
    'tld-cn': ('tld-cn', None),
    'geolocation-!cn': ('geolocation-!cn', None),
    'private': ('private', None),
    'category-ads-all': ('category-ads-all', None),
    # Prevent applications from bypassing Bifrost's signed DNS policy with
    # their own encrypted/HTTP DNS endpoints. The runtime keeps the two
    # configured Bifrost DoH hosts as explicit higher-priority exceptions.
    'category-doh': ('category-doh', None),
    'category-httpdns-cn': ('category-httpdns-cn', None),
    'openai': ('openai', None),
    # High-value foreign service categories are exported as compact sing-box
    # rule sets. Keeping these ahead of broad CN/non-CN fallback protects us
    # from occasional upstream overlap/misclassification while avoiding a
    # giant per-domain rule chain on the hot path.
    'google': ('google', None),
    'github': ('github', None),
    'category-ai-!cn': ('category-ai-!cn', None),
    'category-scholar-!cn': ('category-scholar-!cn', None),
    'category-anticensorship': ('category-anticensorship', None),
    'category-browser-!cn': ('category-browser-!cn', None),
    'category-cdn-!cn': ('category-cdn-!cn', None),
    'category-companies@!cn': ('category-companies', '!cn'),
    'category-games-!cn': ('category-games-!cn', None),
    'category-social-media-!cn': ('category-social-media-!cn', None),
    'youtube': ('youtube', None),
    'twitter': ('twitter', None),
    'telegram': ('telegram', None),
    'discord': ('discord', None),
    'reddit': ('reddit', None),
    'netflix': ('netflix', None),
    'disney': ('disney', None),
    'spotify': ('spotify', None),
    'tiktok': ('tiktok', None),
    'instagram': ('instagram', None),
    'facebook': ('facebook', None),
    'biliintl': ('biliintl', None),
    'pixiv': ('pixiv', None),
    'apple-cn': ('apple-cn', None),
    'onedrive': ('onedrive', None),
    'category-ai-cn': ('category-ai-cn', None),
    'category-automobile-cn': ('category-automobile-cn', None),
    'category-bank-cn': ('category-bank-cn', None),
    'category-blog-cn': ('category-blog-cn', None),
    'category-cdn-cn': ('category-cdn-cn', None),
    'category-collaborate-cn': ('category-collaborate-cn', None),
    'category-documents-cn': ('category-documents-cn', None),
    'category-education-cn': ('category-education-cn', None),
    'category-electronic-cn': ('category-electronic-cn', None),
    # `microsoft@cn`, `steam@cn` and `category-games@cn` are attribute
    # projections inside their base GeoSite entries, not standalone countries.
    'microsoft@cn': ('microsoft', 'cn'),
    'steam@cn': ('steam', 'cn'),
    'category-games@cn': ('category-games', 'cn'),
    'category-companies@cn': ('category-companies', 'cn'),
    'category-dev@cn': ('category-dev', 'cn'),
    'category-ecommerce@cn': ('category-ecommerce', 'cn'),
}
countries = {country for country, _ in categories.values()}

def domain_has_attribute(raw, expected):
    if expected is None:
        return True
    for key, value in fields(raw):
        if key != 3:
            continue
        attribute = list(fields(value))
        name = next((item.decode().lower() for field, item in attribute if field == 1), None)
        enabled = next((item for field, item in attribute if field == 2), 0)
        if name == expected and enabled:
            return True
    return False

found = set()
for number, site in fields((source / 'geosite.dat').read_bytes()):
    assert number == 1
    values = list(fields(site))
    country = next(v.decode().lower() for k, v in values if k == 1)
    if country not in countries: continue
    for name, (base_country, required_attribute) in categories.items():
        if country != base_country:
            continue
        rule = {}
        for key, raw in values:
            if key != 2 or not domain_has_attribute(raw, required_attribute):
                continue
            domain = dict(fields(raw))
            kind = {0: 'domain_keyword', 1: 'domain_regex', 2: 'domain_suffix', 3: 'domain'}[domain.get(1, 0)]
            rule.setdefault(kind, []).append(domain[2].decode())
        if not rule:
            continue
        for kind in rule: rule[kind] = sorted(set(rule[kind]))
        save('geosite-' + name, rule); found.add(name)
assert found == set(categories), f'missing geosite categories: {sorted(set(categories) - found)}'
if maxminddb is not None:
    with maxminddb.open_database(str(source / 'geoip.metadb')) as database:
        cidrs = [str(network) for network, country in database
                 if country == 'cn' or isinstance(country, list) and 'cn' in country]
    assert cidrs
    save('geoip-cn', {'ip_cidr': cidrs})
else:
    # Do not silently trust an arbitrary old rule file.  This fallback exists
    # for restricted build hosts that already have the exact pinned GeoIP
    # export but cannot install Python packages during verification.
    assert previous_manifest and previous_manifest.get('source_commit') == lock['commit'], 'maxminddb required to regenerate geoip-cn'
    previous = next((row for row in previous_manifest.get('files', []) if row.get('name') == 'geoip-cn.json'), None)
    geoip_path = out / 'geoip-cn.json'
    geoip_bytes = geoip_path.read_bytes()
    assert previous and len(geoip_bytes) == previous['bytes'] and hashlib.sha256(geoip_bytes).hexdigest() == previous['sha256'], 'existing geoip-cn does not match prior pinned manifest'
    manifest['files'].append({'name': 'geoip-cn.json', 'bytes': len(geoip_bytes), 'sha256': hashlib.sha256(geoip_bytes).hexdigest()})
    cidrs = json.loads(geoip_bytes)['rules'][0]['ip_cidr']
    assert cidrs
(out / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n', encoding='utf-8')
print(json.dumps({'files': manifest['files'], 'cn_networks': len(cidrs)}, indent=2))
