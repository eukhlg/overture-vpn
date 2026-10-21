#!/usr/bin/env python3
"""Isolated Docker VPN benchmark; uses disposable test-only credentials."""
import subprocess as sp, pathlib, json, time, argparse
ROOT=pathlib.Path(__file__).resolve().parent
OUT=ROOT/'results'; OUT.mkdir(exist_ok=True)
NET='l2tp-bench-net'; C='l2tp-bench-client'; S='l2tp-bench-server'
def run(*a,check=True):
 r=sp.run(a,text=True,stdout=sp.PIPE,stderr=sp.STDOUT,timeout=90)
 if check and r.returncode: raise RuntimeError(f'{a}: {r.stdout}')
 return r.stdout
def ex(c,s,check=True): return run('docker','exec',c,'sh','-c',s,check=check)
def put(c,path,s):
 sp.run(['docker','exec','-i',c,'sh','-c',f'cat > {path}'],input=s,text=True,check=True)
def clean():
 for c in (C,S): run('docker','rm','-f',c,check=False)
 run('docker','network','rm',NET,check=False)
def setup(kind,cipher,natt):
 clean(); run('docker','network','create','--subnet','172.29.231.0/24',NET)
 for c,ip in ((S,'2'),(C,'3')):
  run('docker','run','-d','--name',c,'--network',NET,'--ip','172.29.231.'+ip,'--cap-add','NET_ADMIN','--cap-add','NET_RAW','--device-cgroup-rule','c 108:0 rwm','--device-cgroup-rule','c 10:200 rwm','l2tp-bench:local')
  ex(c,'mkdir -p /dev/net /run/xl2tpd; mknod /dev/net/tun c 10 200; mknod /dev/ppp c 108 0')
 if kind=='go':
  put(S,'/tmp/server.toml',f'''[server]
listen=":1701"
debug=0
[authentication]
method="pap"
[[authentication.users]]
username="bench"
password="bench-only"
[network]
subnet="10.77.0.0/24"
server_address="1"
client_pool_start="2"
client_pool_size=10
mtu=1400
[tun]
enabled=true
name="bench0"
[ipsec]
enabled=true
pre_shared_key="benchmark-only-psk"
server_id="172.29.231.2"
force_natt={str(natt).lower()}
''')
  ex(S,'l2tp-go --config /tmp/server.toml >/tmp/vpn.log 2>&1 &')
 else:
  put(S,'/etc/xl2tpd/xl2tpd.conf','''[global]
port = 1701
[lns default]
ip range = 10.77.0.2-10.77.0.10
local ip = 10.77.0.1
require authentication = yes
pppoptfile = /etc/ppp/options.bench
''')
  put(S,'/etc/ppp/options.bench','debug\nlogfile /tmp/ppp.log\ndefault-asyncmap\nauth\nrequire-pap\nrefuse-chap\nrefuse-mschap\nrefuse-mschap-v2\nmtu 1400\nmru 1400\nnoccp\nnodefaultroute\n')
  put(S,'/etc/ppp/pap-secrets','"bench" * "bench-only" *\n')
  ex(S,'xl2tpd -D >/tmp/vpn.log 2>&1 &')
 for c in ([C,S] if kind=='strongswan' else [C]):
  client=c==C
  put(c,'/etc/strongswan.d/charon/bypass-lan.conf','bypass-lan { load = no }\n')
  put(c,'/etc/ipsec.conf',f'''config setup
 charondebug="ike 1, knl 1"
conn bench
 keyexchange=ikev1
 type=transport
 authby=psk
 left={'172.29.231.3' if client else '172.29.231.2'}
 leftprotoport=17/1701
 right={'172.29.231.2' if client else '172.29.231.3'}
 rightprotoport=17/1701
 ike=aes128-sha1-modp2048!
 esp={cipher}-sha1!
 forceencaps={'yes' if natt else 'no'}
 keylife=1h
 rekey=no
 auto={'add' if client else 'add'}
''')
  put(c,'/etc/ipsec.secrets',': PSK "benchmark-only-psk"\n')
  ex(c,'ipsec start >/tmp/ipsec.log 2>&1')
 time.sleep(2)
 negotiation=ex(C,'ipsec up bench',check=False)
 (OUT/f'{kind}-{cipher}-{natt}-negotiation.txt').write_text(negotiation)
 if 'established successfully' not in negotiation: raise RuntimeError(negotiation)
 put(C,'/etc/xl2tpd/xl2tpd.conf','''[global]
port = 1701
[lac bench]
lns = 172.29.231.2
pppoptfile = /etc/ppp/options.bench
''')
 put(C,'/etc/ppp/options.bench','debug\nlogfile /tmp/ppp.log\ndefault-asyncmap\nuser bench\npassword bench-only\nnoauth\nmtu 1400\nmru 1400\nnoccp\nnodefaultroute\n')
 ex(C,'xl2tpd -D >/tmp/vpn.log 2>&1 &')
 time.sleep(1); ex(C,'echo "c bench" > /run/xl2tpd/l2tp-control')
 for _ in range(20):
  if '10.77.0.2' in ex(C,'ip -4 addr show'): break
  time.sleep(1)
 else: raise RuntimeError(ex(C,'cat /tmp/vpn.log /tmp/ppp.log 2>/dev/null; true')+'\nSERVER\n'+ex(S,'cat /tmp/vpn.log /tmp/ppp.log 2>/dev/null; true'))
 ex(C,'ping -c 2 -W 2 10.77.0.1')
 ex(S,'iperf3 -s -D')
 (OUT/f'{kind}-{cipher}-{natt}-status.txt').write_text(ex(C,'ipsec statusall; ip -s xfrm policy; ip -4 addr')+ex(S,'uname -a; iperf3 --version; ipsec --version'))
def main():
 matrix=[(k,c,n) for c in ('aes128','aes192','aes256','3des') for n in (False,True) for k in ('go','strongswan')]
 parser=argparse.ArgumentParser(description=__doc__)
 parser.add_argument('--server',choices=['go','strongswan'])
 parser.add_argument('--cipher',choices=['aes128','aes192','aes256','3des'])
 parser.add_argument('--transport',choices=['esp','natt'])
 parser.add_argument('--trials',type=int,default=2)
 parser.add_argument('--force',action='store_true')
 args=parser.parse_args()
 matrix=[(k,c,n) for k,c,n in matrix if (not args.server or k==args.server) and (not args.cipher or c==args.cipher) and (not args.transport or n==(args.transport=='natt'))]
 if args.trials<1: parser.error('--trials must be positive')
 try:
  for kind,cipher,natt in matrix:
   if args.force:
    archive=OUT/'previous-runs'/time.strftime('%Y%m%d-%H%M%S')
    for old in list(OUT.glob(f'{kind}-{cipher}-*')):
     if old.name.startswith(f'{kind}-{cipher}-{natt}-') or old.name.startswith(f'{kind}-{cipher}-{"natt" if natt else "esp"}-'):
      archive.mkdir(parents=True,exist_ok=True); old.rename(archive/old.name)
   if (OUT/f'{kind}-{cipher}-{natt}-after.txt').exists():
    print('SKIP completed',kind,cipher,natt,flush=True); continue
   print('SETUP',kind,cipher,natt,flush=True)
   try: setup(kind,cipher,natt)
   except Exception as e:
    (OUT/f'{kind}-{cipher}-{natt}-error.txt').write_text(str(e))
    print('FAILED',str(e),flush=True)
    continue
   (OUT/f'{kind}-{cipher}-{natt}-error.txt').unlink(missing_ok=True)
   for direction in ('upload','download'):
    for trial in range(args.trials):
     name=f'{kind}-{cipher}-{"natt" if natt else "esp"}-{direction}-{trial}'
     result=ex(C,f'iperf3 -c 10.77.0.1 -t 10 -O 2 -J {"-R" if direction=="download" else ""}',check=False)
     (OUT/(name+'.json')).write_text(result)
     data=json.loads(result)
     if 'error' in data: raise RuntimeError(data['error'])
     print(name,round(data['end']['sum_received']['bits_per_second']/1e6,2),flush=True)
   (OUT/f'{kind}-{cipher}-{natt}-after.txt').write_text(ex(C,'ipsec statusall; ip -s xfrm policy'))
 finally: clean()
if __name__=='__main__': main()
