"""Endpoint script integration tests with isolated paths and mocked host services."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
import sys

ROOT = Path(__file__).resolve().parents[1]
DISPATCH = r'''#!/usr/bin/env python3
import os, sys, subprocess
from pathlib import Path
name = Path(sys.argv[0]).name
args = sys.argv[1:]
root = Path(os.environ['ENDPOINT_TEST_ROOT'])
with (root/'commands.jsonl').open('a') as log:
 import json
 log.write(json.dumps([name,*args])+'\n')
if name == 'ss':
 port = args[-1].split(':')[-1] if args else ''
 protocol = 'udp' if any('u' in a and a.startswith('-') for a in args) else 'tcp'
 if port == os.environ.get('BUSY_PORT','') and protocol == os.environ.get('BUSY_PROTOCOL','tcp'):
  print('LISTEN 0 1 *:'+port+' *:* users:(("other-service",pid=1,fd=1))')
 elif port == '443' and protocol == 'udp':
  print('UNCONN 0 0 *:443 *:* users:(("hysteria",pid=2,fd=2))')
elif name == 'curl':
 if '--data' not in args: print('401')
 elif 'initialize' in args[args.index('--data')+1]: print('{"protocolVersion":"2025-03-26"}')
 elif 'tools/list' in args[args.index('--data')+1]: print('{"tools":["list_projects"]}')
 else: print('{"authentication":"ok"}')
elif name == 'systemctl' or name == 'chown' or name == 'getent' or name == 'runuser':
 pass
elif name == 'install':
 clean=[]; i=0
 while i<len(args):
  if args[i] in ('-o','-g'): i+=2
  else: clean.append(args[i]); i+=1
 sys.exit(subprocess.call(['/usr/bin/install',*clean]))
elif name == 'tar':
 if os.environ.get('FAIL_BACKUP') == '1' and '-czf' in args: sys.exit(1)
 sys.exit(subprocess.call(['/usr/bin/tar',*args]))
elif name == 'ufw':
 if args == ['status']:
  print('Status: active\n80/tcp ALLOW Anywhere')
elif name == 'caddy':
 if args and args[0] == 'validate':
  assert os.environ.get('MOORY_TOKEN') == 'endpoint-test-placeholder'
  if os.environ.get('FAIL_VALIDATE') == '1': sys.exit(1)
'''


class EndpointPorts(unittest.TestCase):
    def run_endpoint(self, public='8443', *, busy='', protocol='tcp', fail_validate=False, fail_backup=False, legacy=False):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        (root/'etc/moory').mkdir(parents=True)
        (root/'etc/caddy/conf.d').mkdir(parents=True)
        (root/'root').mkdir()
        (root/'bin').mkdir()
        (root/'commands.jsonl').touch()
        original = '{\n    servers {\n        protocols h1 h2\n    }\n}\n:80 {\n    respond "existing-site"\n}\nimport /etc/caddy/conf.d/*.caddy\n'
        (root/'etc/caddy/Caddyfile').write_text(original)
        config = f'MOORY_ROOT=/srv/moory\nMOORY_PORT=8787\nMOORY_DOMAIN={"mcp.example.test" if legacy else ""}\n'
        (root/'etc/moory/install.env').write_text(config)
        (root/'etc/moory/caddy.env').write_text('MOORY_TOKEN=endpoint-test-placeholder\n')
        for name in ('ss','systemctl','getent','install','chown','ufw','caddy','tar','curl','runuser'):
            path = root/'bin'/name
            path.write_text(DISPATCH)
            path.chmod(0o755)
        text = (ROOT/'scripts/configure-caddy.sh').read_text()
        text = text.replace('[[ ${EUID} -eq 0 ]]','[[ 1 -eq 1 ]]')
        text = text.replace('/etc/', f'{root}/etc/').replace('/root/',f'{root}/root/')
        text = text.replace('[[ ! -e /$path ]]',f'[[ ! -e {root}/$path ]]')
        text = text.replace('rm -f "/$path"', f'rm -f "{root}/$path"')
        text = text.replace('-C / ', f'-C {root} ')
        # The source imports a literal host path; fixtures use the sandbox path.
        original = original.replace('/etc/',f'{root}/etc/')
        (root/'etc/caddy/Caddyfile').write_text(original)
        script = root/'configure.sh'; script.write_text(text)
        env = {**os.environ, 'PATH':f'{root}/bin:'+os.environ['PATH'], 'ENDPOINT_TEST_ROOT':str(root),
               'BUSY_PORT':busy,'BUSY_PROTOCOL':protocol,'FAIL_VALIDATE':str(int(fail_validate)), 'FAIL_BACKUP':str(int(fail_backup))}
        args = ['bash',str(script),'mcp.example.test','8787']
        if public is not None: args.append(public)
        result = subprocess.run(args,env=env,text=True,capture_output=True)
        commands = [json.loads(x) for x in (root/'commands.jsonl').read_text().splitlines()]
        return root,original,config,result,commands

    def test_default_8443_preserves_shared_options_and_udp443(self):
        root,original,_,result,commands = self.run_endpoint(None)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual((root/'etc/caddy/Caddyfile').read_text(),original)
        site = (root/'etc/caddy/conf.d/moory.caddy').read_text()
        self.assertIn('https://mcp.example.test:8443 {',site)
        self.assertIn('127.0.0.1:8787',site)
        self.assertIn('disable_tlsalpn_challenge',site)
        self.assertIn('MOORY_HTTPS_PORT=8443',(root/'etc/moory/install.env').read_text())
        self.assertIn('https://mcp.example.test:8443/mcp',result.stdout)
        self.assertIn(['ufw','allow','8443/tcp'],commands)
        self.assertNotIn(['ufw','allow','443/tcp'],commands)
        self.assertFalse(any(c[0]=='ss' and 'sport = :443' in c for c in commands))

    def test_alternative_9443(self):
        root,_,_,result,_ = self.run_endpoint('9443')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn(':9443/mcp',result.stdout)
        self.assertIn('MOORY_HTTPS_PORT=9443',(root/'etc/moory/install.env').read_text())

    def test_conflicts_refuse_without_mutation(self):
        for protocol in ('tcp','udp'):
            with self.subTest(protocol=protocol):
                root,original,config,result,commands=self.run_endpoint(busy='8443',protocol=protocol)
                self.assertNotEqual(result.returncode,0)
                self.assertEqual((root/'etc/moory/install.env').read_text(),config)
                self.assertEqual((root/'etc/caddy/Caddyfile').read_text(),original)
                self.assertFalse(any(c[0]=='systemctl' for c in commands))

    def test_validation_failure_rolls_back_and_keeps_existing_firewall_rules(self):
        root,original,config,result,commands=self.run_endpoint(fail_validate=True)
        self.assertNotEqual(result.returncode,0)
        self.assertEqual((root/'etc/moory/install.env').read_text(),config)
        self.assertEqual((root/'etc/caddy/Caddyfile').read_text(),original)
        self.assertFalse((root/'etc/caddy/conf.d/moory.caddy').exists())
        self.assertIn(['ufw','--force','delete','allow','8443/tcp'],commands)
        self.assertNotIn(['ufw','--force','delete','allow','80/tcp'],commands)

    def test_backup_failure_blocks_mutation(self):
        root,original,config,result,commands=self.run_endpoint(fail_backup=True)
        self.assertNotEqual(result.returncode,0)
        self.assertEqual((root/'etc/moory/install.env').read_text(),config)
        self.assertEqual((root/'etc/caddy/Caddyfile').read_text(),original)
        self.assertFalse(any(c[0]=='systemctl' for c in commands))

    def test_healthcheck_uses_saved_public_port_and_legacy_443(self):
        for port in ('8443','9443','443'):
            with self.subTest(port=port):
                root,_,_,_,_=self.run_endpoint('8443')
                runtime=root/'srv/moory'
                for path in ('app','config','repos','logs','venv/bin'):
                    (runtime/path).mkdir(parents=True,exist_ok=True)
                (runtime/'app/server.py').write_text('# fixture\n')
                (runtime/'config/projects.json').write_text('{}')
                (runtime/'config/github-auth.env').write_text('# fixture\n')
                (runtime/'logs/audit.jsonl').touch()
                (runtime/'venv/bin/python').symlink_to(sys.executable)
                config=f'MOORY_ROOT={runtime}\nMOORY_PORT=8787\nMOORY_DOMAIN=mcp.example.test\n'
                if port != '443': config+=f'MOORY_HTTPS_PORT={port}\n'
                (root/'etc/moory/install.env').write_text(config)
                script=root/'health.sh'
                script.write_text((ROOT/'scripts/healthcheck.sh').read_text().replace('/etc/',f'{root}/etc/'))
                (root/'commands.jsonl').write_text('')
                env={**os.environ,'PATH':f'{root}/bin:'+os.environ['PATH'],'ENDPOINT_TEST_ROOT':str(root)}
                result=subprocess.run(['bash',str(script)],env=env,capture_output=True,text=True)
                self.assertEqual(result.returncode,0,result.stderr)
                calls=[json.loads(x) for x in (root/'commands.jsonl').read_text().splitlines()]
                expected='https://mcp.example.test'+('' if port=='443' else ':'+port)+'/mcp'
                urls=[c[-1] for c in calls if c[0]=='curl']
                self.assertEqual(urls,[expected]*4)

    def test_legacy_config_retains_443(self):
        root,_,_,result,_=self.run_endpoint(None,legacy=True)
        # The fixture deliberately has Hysteria on UDP443: refuse, never move
        # an existing deployment silently to a different public port.
        self.assertNotEqual(result.returncode,0)
        self.assertIn('udp port 443 is occupied',result.stderr)
        self.assertNotIn('MOORY_HTTPS_PORT=',(root/'etc/moory/install.env').read_text())

    def test_invalid_or_colliding_public_port(self):
        for port in ('80','8787','0','65536','08443','8443;false'):
            with self.subTest(port=port):
                _,_,_,result,commands=self.run_endpoint(port)
                self.assertNotEqual(result.returncode,0)
                self.assertFalse(any(c[0]=='systemctl' for c in commands))


if __name__ == '__main__':
    unittest.main()
