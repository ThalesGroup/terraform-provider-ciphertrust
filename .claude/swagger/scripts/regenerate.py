#!/usr/bin/env python3
"""
Regenerate .claude/swagger/{index.md, operations.md, definitions.json, areas/*.json}
from definition-beta.json.

Run from the repo root:
    python .claude/swagger/scripts/regenerate.py

When to run:
- After Thales publishes a new version of definition-beta.json.
- After editing area_for() to re-bucket operations.

What it produces:
- .claude/swagger/index.md         small (~4 KB) navigation index
- .claude/swagger/operations.md    one line per operation, grep-searchable (~260 KB)
- .claude/swagger/areas/*.json     per-area swagger (3 MB total) using $ref to definitions.json
- .claude/swagger/definitions.json shared schema fragments (~635 KB)

Why splits + dedup:
- definition-beta.json is ~14.8 MB / ~3.7M tokens - unloadable.
- Each area JSON is 16-430 KB after dedup.
- Common subtrees (auth headers, error responses, etc.) are hoisted into
  definitions.json - eliminating ~3.3 MB of duplicate content across area files.
- Combined size: ~3.6 MB, 47% smaller than naive splits.
"""
import json, os, re, sys, hashlib
from collections import defaultdict

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
SPEC_PATH = os.path.join(REPO_ROOT, 'definition-beta.json')
OUT_DIR   = os.path.join(REPO_ROOT, '.claude', 'swagger')

AREA_DESC = {
    'auth-users':       'Authentication, users, groups, domains, permissions',
    'cckm-aws':         'CCKM AWS - keys, KMS, custom key stores, XKS',
    'cckm-azure':       'CCKM Azure - keys, certificates, secrets',
    'cckm-google':      'CCKM Google Cloud - keys, Workspace CSE, EKM',
    'cckm-hsm':         'CCKM HSM Luna keys',
    'cckm-microsoft':   'CCKM Microsoft DKE',
    'cckm-misc':        'CCKM smaller integrations (catch-all)',
    'cckm-oracle':      'CCKM Oracle Cloud Infrastructure keys, vaults',
    'cckm-sap':         'CCKM SAP Data Custodian keys, HYOK',
    'cckm-sfdc':        'CCKM Salesforce tenant secrets',
    'cm-admin':         'CM admin - Certificate Authority, SSH keys, Interfaces, SNMP, NAE-XML, Quorum',
    'cm-keys':          'CM core keys API (/v1/vault)',
    'cm-logs':          'Audit records, logger config, syslog records',
    'cm-misc':          'Misc CM endpoints not in another bucket',
    'cm-ops':           'Operational: licensing, backups, migrations, scheduler',
    'cm-system':        'System, configs, cluster',
    'connections':      'All connectionmgmt endpoints (AWS/Azure/GCP/OCI/SCP/etc.)',
    'cte':              'CipherTrust Transparent Encryption - clients, policies, rules, profiles, guardpoints',
    'data-protection':  'Data Protection - BDT jobs/policies, Crypto, key formats',
    'ddc':              'Data Discovery & Classification',
    'protect-app':      'ProtectApp',
    'protect-file':     'ProtectFile clients, clusters',
}

# Dedup tuning
DEDUP_MIN_COUNT = 3      # must appear at least this many times to be hoisted
DEDUP_MIN_SIZE  = 150    # subtree must be at least this many bytes (serialized) to be hoisted


def area_for(p, tags):
    primary = (tags or ['Misc'])[0]
    if primary.startswith('CCKM/'):
        sub = primary.split('/', 1)[1].lower()
        if 'aws' in sub: return 'cckm-aws'
        if 'azure' in sub: return 'cckm-azure'
        if 'google' in sub: return 'cckm-google'
        if 'oracle' in sub: return 'cckm-oracle'
        if 'sap' in sub: return 'cckm-sap'
        if 'hsm' in sub or 'luna' in sub: return 'cckm-hsm'
        if 'microsoft' in sub or 'dke' in sub: return 'cckm-microsoft'
        if 'sfdc' in sub or 'salesforce' in sub: return 'cckm-sfdc'
        return 'cckm-misc'
    if primary.startswith('CTE'): return 'cte'
    if primary.startswith('DDC'): return 'ddc'
    if primary.startswith('ProtectFile'): return 'protect-file'
    if 'ProtectDB' in primary: return 'protect-db'
    if primary.startswith('ProtectApp'): return 'protect-app'
    if primary.startswith('Data Protection') or 'BDT' in primary or 'Crypto' in primary:
        return 'data-protection'
    if p.startswith('/v1/connectionmgmt'): return 'connections'
    if p.startswith('/v1/auth') or primary in ('Permissions', 'Users', 'Domains', 'Groups'):
        return 'auth-users'
    if p.startswith('/v1/system') or p.startswith('/v1/configs') or p.startswith('/v1/cluster'):
        return 'cm-system'
    if p.startswith('/v1/vault') or primary == 'Keys': return 'cm-keys'
    if primary in ('Certificate Authority', 'SSH Keys', 'Interfaces', 'SNMP', 'NAE-XML', 'Quorum'):
        return 'cm-admin'
    if p.startswith('/v1/audit') or p.startswith('/v1/logs') or primary in ('Records', 'Logger Config', 'syslog'):
        return 'cm-logs'
    if (p.startswith('/v1/licensing') or p.startswith('/v1/backups')
            or p.startswith('/v1/migrations') or p.startswith('/v1/scheduler')):
        return 'cm-ops'
    return 'cm-misc'


def chash(node):
    return hashlib.md5(json.dumps(node, sort_keys=True, separators=(',', ':')).encode('utf-8')).hexdigest()


def collect_subtrees(node, file_key, path, occurrences):
    """Walk and record every dict subtree by hash with its (file_key, path) location."""
    if isinstance(node, dict):
        ser = json.dumps(node, sort_keys=True, separators=(',', ':'))
        if len(ser) >= DEDUP_MIN_SIZE and len(node) >= 1:
            occurrences[chash(node)].append((file_key, tuple(path), node))
        for k, v in node.items():
            collect_subtrees(v, file_key, path + [('k', k)], occurrences)
    elif isinstance(node, list):
        for i, v in enumerate(node):
            collect_subtrees(v, file_key, path + [('i', i)], occurrences)


def hash_at(spec, path):
    try:
        node = spec['paths']
        for kind, k in path:
            node = node[k]
        return chash(node) if isinstance(node, dict) else None
    except (KeyError, IndexError, TypeError):
        return None


def replace_at(spec, path, new_value):
    node = spec['paths']
    for kind, k in path[:-1]:
        node = node[k]
    parent_kind, last_k = path[-1]
    node[last_k] = new_value


def main():
    if not os.path.exists(SPEC_PATH):
        print(f"ERROR: {SPEC_PATH} not found", file=sys.stderr)
        sys.exit(1)

    with open(SPEC_PATH, 'r', encoding='utf-8') as f:
        spec = json.load(f)
    paths = spec.get('paths', {})

    # Bucket paths by area + collect ops for the TOC
    area_paths = defaultdict(dict)
    all_ops = []
    for p, ops in paths.items():
        chosen_area = None
        for verb, op in ops.items():
            if verb not in ('get', 'post', 'put', 'patch', 'delete'):
                continue
            tags = op.get('tags', [])
            chosen_area = area_for(p, tags)
            all_ops.append({
                'area': chosen_area,
                'verb': verb.upper(),
                'path': p,
                'tag':  (tags or ['(none)'])[0],
                'opId': op.get('operationId', ''),
                'summary': (op.get('summary', '') or '').strip(),
            })
        if chosen_area:
            area_paths[chosen_area][p] = ops

    # Build per-area self-contained specs (no $refs yet)
    os.makedirs(os.path.join(OUT_DIR, 'areas'), exist_ok=True)
    area_specs = {}
    for area, ap in sorted(area_paths.items()):
        op_count = sum(1 for _p, _ops in ap.items() for v in _ops if v in ('get', 'post', 'put', 'patch', 'delete'))
        area_specs[area] = {
            'swagger':      spec.get('swagger'),
            'info':         spec.get('info'),
            'basePath':     spec.get('basePath'),
            'schemes':      spec.get('schemes'),
            '__area':       area,
            '__op_count':   op_count,
            '__path_count': len(ap),
            'paths':        ap,
        }

    # --- Dedup pass ---
    # Collect every dict subtree across all area files
    occurrences = defaultdict(list)
    for area, sp in area_specs.items():
        collect_subtrees(sp.get('paths', {}), area, [], occurrences)

    # Candidates: count >= DEDUP_MIN_COUNT, sorted by size desc (parents before children)
    candidates = []
    for h, locs in occurrences.items():
        if len(locs) >= DEDUP_MIN_COUNT:
            sz = len(json.dumps(locs[0][2], separators=(',', ':')))
            candidates.append((h, len(locs), sz, locs))
    candidates.sort(key=lambda x: -x[2])

    definitions = {}
    name_counter = 0
    for h, _count, _size, locs in candidates:
        valid = [(f, path) for f, path, _orig in locs if hash_at(area_specs[f], path) == h]
        if len(valid) < DEDUP_MIN_COUNT:
            continue  # already absorbed by an ancestor hoist
        name_counter += 1
        name = f"D{name_counter:04d}"
        definitions[name] = locs[0][2]
        ref_obj = {"$ref": f"../definitions.json#/{name}"}
        for f, path in valid:
            replace_at(area_specs[f], path, ref_obj)

    # Write area files (compact)
    manifest = []
    for area, sp in area_specs.items():
        out_path = os.path.join(OUT_DIR, 'areas', f'{area}.json')
        with open(out_path, 'w', encoding='utf-8') as o:
            json.dump(sp, o, separators=(',', ':'))
        manifest.append((area, sp['__op_count'], sp['__path_count'], os.path.getsize(out_path)))

    # Write shared definitions.json
    defs_path = os.path.join(OUT_DIR, 'definitions.json')
    with open(defs_path, 'w', encoding='utf-8') as o:
        json.dump({'__count': len(definitions), 'definitions': definitions}, o, separators=(',', ':'))
    defs_sz = os.path.getsize(defs_path)

    # index.md
    lines = ['# CipherTrust Swagger - pre-split index', '',
             'Source: [definition-beta.json](../../definition-beta.json) (~14.8 MB / ~3.7M tokens - DO NOT load).', '',
             'Per-area JSON splits under [areas/](areas/) reference a shared [definitions.json](definitions.json) (~635 KB) via `$ref`.',
             'For most resource lookups, load only the area file - resolve `$ref`s by greping `definitions.json` for the specific `D####` name.', '',
             'For a searchable list of every operation across all areas, see [operations.md](operations.md).', '',
             '## Areas', '',
             '| Area | Ops | Paths | Size (KB) | Description |',
             '|---|---:|---:|---:|---|']
    for a, o, p, sz in sorted(manifest, key=lambda x: x[0]):
        lines.append(f'| [`{a}`](areas/{a}.json) | {o} | {p} | {sz // 1024} | {AREA_DESC.get(a, "")} |')
    lines += ['', f'**Shared definitions:** [definitions.json](definitions.json) ({defs_sz // 1024} KB, {len(definitions)} entries)', '',
              '## How to use this', '',
              '1. **Decide which area you need.** When adding a resource, the area name usually maps to the provider subsystem (e.g. CCKM Azure -> `cckm-azure`).',
              '2. **Read the area file.** Each contains operation paths with inlined schemas (small ones) and `"$ref": "../definitions.json#/D####"` (large/shared ones).',
              '3. **Resolve refs on demand.** When you hit a `$ref` you need, grep `definitions.json` for `"D####":` and read those lines only. Do NOT load the entire definitions.json.',
              '4. **Search across all areas:** grep [operations.md](operations.md) for the keyword (path fragment, tag, summary text, or operationId), then jump to the area file.',
              '5. **DO NOT load `definition-beta.json` directly.** It is ~3.7M tokens.', '',
              '## Regenerating', '',
              'Run `python .claude/swagger/scripts/regenerate.py` after Thales publishes a new `definition-beta.json`.', '']
    with open(os.path.join(OUT_DIR, 'index.md'), 'w', encoding='utf-8') as o:
        o.write('\n'.join(lines))

    # operations.md
    ops_lines = ['# All operations', '',
                 'One line per swagger operation. Format: `<area> | <VERB> <path> | <tag> | <summary>`.', '',
                 'Grep this file for keywords (e.g. "azure key", "rotate", "create-hyok"), then open the area JSON listed in the left column.', '',
                 '```']
    for op in sorted(all_ops, key=lambda x: (x['area'], x['path'], x['verb'])):
        summary = (op['summary'] or '').replace('\n', ' ').replace('\r', '')[:100]
        ops_lines.append(f"{op['area']:<18} | {op['verb']:<6} {op['path']:<70} | {op['tag']:<35} | {summary}")
    ops_lines.append('```')
    with open(os.path.join(OUT_DIR, 'operations.md'), 'w', encoding='utf-8') as o:
        o.write('\n'.join(ops_lines))

    total_areas = sum(m[3] for m in manifest)
    combined = total_areas + defs_sz
    print(f"Wrote {len(manifest)} area files: {total_areas / 1024:.0f} KB ({total_areas / 1024 / 1024:.2f} MB)")
    print(f"Shared definitions.json: {defs_sz / 1024:.0f} KB ({defs_sz / 1024 / 1024:.2f} MB), {len(definitions)} entries")
    print(f"Combined: {combined / 1024:.0f} KB ({combined / 1024 / 1024:.2f} MB)")
    print(f"Index: {os.path.getsize(os.path.join(OUT_DIR, 'index.md')) / 1024:.1f} KB")
    print(f"Operations: {os.path.getsize(os.path.join(OUT_DIR, 'operations.md')) / 1024:.1f} KB")


if __name__ == '__main__':
    main()
