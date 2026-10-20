import importlib.util,pathlib,json,re,hashlib,subprocess
ROOT=pathlib.Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('harness',ROOT/'interop-harness.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
m.NET='overture-buffer-bench-net';m.C='overture-buffer-bench-client';m.S='overture-buffer-bench-server'
original_put=m.put
original_ex=m.ex
binary=None

def put(c,path,data):
 if path=='/etc/ipsec.conf':data+=' replay_window=1024\n'
 return original_put(c,path,data)

def ex(c,command,check=True):
 if c==m.S and command.startswith('l2tp-go --config'):
  m.run('docker','cp',str(binary),m.S+':/usr/local/bin/l2tp-go')
 return original_ex(c,command,check=check)
m.put=put;m.ex=ex
try:
 for natt in [False,True]:
  for label,kind in [('before','go'),('after','go'),('reference','strongswan')]:
   binary=ROOT/(label+'-vpn');mode='natt' if natt else 'esp';name=label+'-aes128-'+mode
   m.OUT=ROOT/'results'/name;m.OUT.mkdir(parents=True,exist_ok=True)
   print('SETUP',name,flush=True)
   (m.OUT/'error.txt').unlink(missing_ok=True)
   try:
    m.setup(kind,'aes128',natt)
    for c in ([m.C,m.S] if kind=='strongswan' else [m.C]):
     state=m.ex(c,'ip -s xfrm state');state=re.sub(r'0x[0-9a-f]{32,}', '[redacted-test-key]', state);(m.OUT/(c+'-state.txt')).write_text(state)
     windows=re.findall(r'replay_window\s+(\d+)',state)
     assert windows and all(int(w)==1024 for w in windows),windows
    for direction in ['upload','download']:
     for trial in range(2):
      raw=m.ex(m.C,'iperf3 -c 10.77.0.1 -t 10 -O 2 -J'+(' -R' if direction=='download' else ''))
      (m.OUT/f'{direction}-{trial}.json').write_text(raw)
      result=json.loads(raw);assert 'error' not in result,result.get('error')
      assert result['end']['sum_received']['seconds']>9
      print(name,direction,trial,round(result['end']['sum_received']['bits_per_second']/1e6,2),flush=True)
    for c in [m.C,m.S]:
     (m.OUT/(c+'-xfrm.txt')).write_text(m.ex(c,'cat /proc/net/xfrm_stat'))
     (m.OUT/(c+'-vpn.log')).write_text(m.ex(c,'cat /tmp/vpn.log /tmp/ppp.log 2>/dev/null; true'))
    state=m.ex(m.C,'ipsec statusall; ip -4 addr; ip -d link show');(m.OUT/'status.txt').write_text(state)
    assert 'AES_CBC_128/HMAC_SHA1_96' in state
    assert ('ESP in UDP' in state)==natt
    (m.OUT/'complete.txt').write_text('Verified cipher, replay windows and measured both directions.\n')
   except Exception as e:
    (m.OUT/'error.txt').write_text(str(e));raise
finally:m.clean()
