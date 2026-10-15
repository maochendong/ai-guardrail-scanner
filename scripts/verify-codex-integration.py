#!/usr/bin/env python3
"""Verify the configured scanner through Codex without starting a model turn."""
from report_schema import verify_unknowns, verified_report_content
from pathlib import Path
import subprocess,json,threading,queue,time,tomllib,argparse,os
if not __debug__:
    raise RuntimeError('Verification requires assertions; disable -O and PYTHONOPTIMIZE.')
parser=argparse.ArgumentParser(description='Verify an installed scanner through an actual ephemeral Codex app-server thread.')
parser.add_argument('--project',type=Path,action='append',required=True)
parser.add_argument('--output',type=Path,required=True)
parser.add_argument('--profile',choices=['generic','bank-common','bank-customer','bank-internal','bank-all'],default='generic')
parser.add_argument('--bank-policy',type=Path)
parser.add_argument('--expect-java-functions',action='store_true')
parser.add_argument('--expect-python-rag',action='store_true')
parser.add_argument('--require-python-parse-success',action='store_true')
parser.add_argument('--require-resolved-python-clients',action='store_true')
parser.add_argument('--expect-python-guard-results',action='store_true')
args=parser.parse_args()
if args.bank_policy is not None:
    args.bank_policy=args.bank_policy.resolve()
    assert args.bank_policy.is_file(),args.bank_policy
ROOT=Path(__file__).resolve().parent.parent
OUT=args.output.resolve()
if OUT.exists() and any(OUT.iterdir()):
    parser.error('--output must be new or empty so stale Codex evidence cannot be reused')
OUT.mkdir(parents=True,exist_ok=True)
config=tomllib.loads((Path(os.environ.get('CODEX_HOME',str(Path.home()/'.codex')))/'config.toml').read_text())
installed_args=config.get('mcp_servers',{}).get('ai-guardrail-scanner',{}).get('args',[])
def installed_option(name):
    assert installed_args.count(name)<=1,('Duplicate configured scanner option',name)
    if name not in installed_args:return None
    index=installed_args.index(name)
    assert index+1<len(installed_args),('Missing configured scanner option value',name)
    return installed_args[index+1]
assert (installed_option('--profile') or 'generic')==args.profile,'Configured scanner profile differs from --profile'
installed_policy=installed_option('--bank-policy')
assert (Path(installed_policy).resolve() if installed_policy is not None else None)==args.bank_policy,'Configured scanner policy differs from --bank-policy'
installed_output=installed_option('--output')
assert installed_output is not None and Path(installed_output).is_absolute(),'Configured scanner output must be an absolute directory'
cmd=['codex','app-server','--stdio']
for name in config.get('mcp_servers',{}):
    if name!='ai-guardrail-scanner':cmd+=['-c','mcp_servers.'+name+'.enabled=false']
for name in config.get('plugins',{}):cmd+=['-c','plugins.'+name+'.enabled=false']
log=(OUT/'codex-app-server.stderr.log').open('w')
p=subprocess.Popen(cmd,cwd=ROOT,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=log,text=True,encoding='utf-8',bufsize=1)
q=queue.Queue();seq=0;events=[]
def reader():
    for line in p.stdout:
        try:q.put(json.loads(line))
        except json.JSONDecodeError:q.put({'invalidProtocol':True})
    q.put({'eof':True})
threading.Thread(target=reader,daemon=True).start()
def rpc(method,params,timeout=60):
    global seq
    seq+=1;identifier=seq
    p.stdin.write(json.dumps({'id':identifier,'method':method,'params':params})+'\n');p.stdin.flush()
    deadline=time.monotonic()+timeout
    while True:
        msg=q.get(timeout=max(.01,deadline-time.monotonic()))
        if msg.get('id')==identifier and ('result'in msg or 'error'in msg):
            if 'error'in msg:raise RuntimeError(method+': '+json.dumps(msg['error']))
            return msg['result']
        if 'id'in msg and 'method'in msg:raise RuntimeError('Unexpected server request '+msg['method'])
        if msg.get('eof') or msg.get('invalidProtocol'):raise RuntimeError('Codex protocol ended')
        events.append(msg.get('method','unknown'))
        if time.monotonic()>deadline:raise TimeoutError(method)
def tool(name,args,expect_error=False):
    result=rpc('mcpServer/tool/call',{'threadId':tid,'server':'ai-guardrail-scanner','tool':name,'arguments':args})
    assert bool(result.get('isError'))==expect_error,(name,result)
    value=json.loads(next(c['text'] for c in result['content'] if c.get('type')=='text'))
    transcript.append({'tool':name,'arguments':args,'isError':bool(result.get('isError')),'result':value})
    return value
def stable_report(report):
    return {key:report[key] for key in ['schemaVersion','ruleSetVersion','sourceDigest','project',
            'complete','securityVerified','policy','gateDecision','unknownSummary','mappingCoverage','assessments','diagnostics']}
def expected_ids(rules,languages,profile):
    ids={r['id'] for r in rules if
         (r['id'].startswith('AI-PY-') and 'python' in languages) or
         (r['id'].startswith('AI-') and not r['id'].startswith('AI-PY-') and 'java' in languages)}
    if profile!='generic':ids.update(['BANK-DATA-001','BANK-IAM-001','BANK-GUARD-001'])
    if profile in ['bank-customer','bank-all']:ids.update(['BANK-CUST-001','BANK-CUST-002'])
    if profile in ['bank-internal','bank-all']:ids.update(['BANK-INTERNAL-001','BANK-INTERNAL-002'])
    return ids
def verify_policy(report):
    assert report['complete'] is False and report['securityVerified'] is False
    assert report['policy']['profile']==args.profile
    policy_input=json.loads(args.bank_policy.read_text()) if args.bank_policy is not None else {'version':1,'contracts':[]}
    assert report['policy']['version']=='bank-policy-v'+str(policy_input['version']),report['policy']
    digest=report['policy']['digest']
    assert len(digest)==64 and all(c in '0123456789abcdef' for c in digest)
    contracts=policy_input.get('contracts', [])
    assert report['policy']['contractCount']==len(contracts)
    assert report['gateDecision']==('BLOCK' if any(a['disposition']=='VIOLATED' for a in report['assessments']) else 'REVIEW')


transcript=[];summary={};stable_reports={}
try:
    init=rpc('initialize',{'clientInfo':{'name':'ai_guardrail_integration_test','version':'0.7.0'},'capabilities':{'experimentalApi':True}})
    p.stdin.write(json.dumps({'method':'initialized'})+'\n');p.stdin.flush()
    started=rpc('thread/start',{'cwd':str(ROOT),'ephemeral':True},timeout=60)
    tid=started['thread']['id']
    print('Codex ephemeral test runtime initialized',flush=True)
    status=rpc('mcpServerStatus/list',{'threadId':tid,'serverName':'ai-guardrail-scanner','limit':10},timeout=60)
    (OUT/'codex-discovery.json').write_text(json.dumps(status,ensure_ascii=False,indent=2)+'\n')
    servers=status.get('data',[])
    server=next(s for s in servers if s['name']=='ai-guardrail-scanner')
    print('MCP discovery:',server.get('runtimeStatus'),list(server['tools']),flush=True)
    assert len(server['tools'])==5
    rules=tool('guardrail_rules',{})
    assert len(rules)==len({r['id'] for r in rules})==33
    assert server['serverInfo']['version']=='0.7.0'
    rejected=tool('guardrail_scan_start',{'repository':'/'},True)
    invalid=tool('guardrail_scan_status',{'scanId':'not-a-scan-id'},True)
    summary={'client':'Codex app-server stdio / mcpServer/tool/call','server':server.get('serverInfo'),'discoveredTools':list(server['tools']),'ruleCount':len(rules),'profile':args.profile,'outsideRootRejected':rejected,'invalidScanIdRejected':invalid,'projects':[]}
    for project in args.project:
        name,path=project.name,str(project.resolve())
        t=time.monotonic();s=tool('guardrail_scan_start',{'repository':path});scanid=s['scanId'];states=[s['state']]
        while s['state']=='RUNNING':
            time.sleep(.2);s=tool('guardrail_scan_status',{'scanId':scanid})
            if s['state']!=states[-1]:states.append(s['state'])
            assert time.monotonic()-t<150
        assert s['state']=='COMPLETED',s
        results={fmt:tool('guardrail_scan_result',{'scanId':scanid,'format':fmt}) for fmt in ['json','markdown','sarif']}
        documents={fmt:verified_report_content(r,fmt,s,installed_output,name) for fmt,r in results.items()}
        report=json.loads(documents['json']);sarif=json.loads(documents['sarif'])
        assert report['schemaVersion']=='1.6'
        assert report['ruleSetVersion']=='java-python-guardrail-v8'
        assert report['runtime']['scannerVersion']=='0.7.0'
        assert report['runtime']['javaVersion'].startswith(('1.7.','1.8.'))
        verify_policy(report)
        assert s['policy']==report['policy']
        assert s['gateDecision']==report['gateDecision']
        verify_unknowns(report,s,sarif['runs'][0]['properties'],documents['markdown'],name)
        if args.require_python_parse_success:
            assert not any(d['code'] in ['PYTHON_PARSE_FAILED','PYTHON_PARSE_DEPTH',
                                        'PYTHON_ANALYSIS_LIMIT','BANK_PYTHON_PARSE_FAILED',
                                        'BANK_PYTHON_ANALYSIS_DEPTH','BANK_PYTHON_ANALYSIS_LIMIT'] for d in report['diagnostics']),name
        if args.require_resolved_python_clients and report['project']['languages']==['python']:
            assert not any(d['code']=='PYTHON_UNRESOLVED_MODEL_CALL' for d in report['diagnostics']),name
        if args.expect_python_guard_results and report['project']['languages']==['python']:
            assert any(a['ruleId']=='AI-PY-007' and a['disposition']=='OBSERVED'
                       and 'consumer-result' in a['explanation'] for a in report['assessments']),name
        assert {a['ruleId'] for a in sarif['runs'][0]['results']}=={
            a['ruleId'] for a in report['assessments'] if a['disposition']=='VIOLATED'}
        assert {a['ruleId'] for a in report['assessments']}==expected_ids(rules,report['project']['languages'],args.profile)
        if args.expect_java_functions and 'java' in report['project']['languages']:
            for rule in ['AI-GW-001','AI-FC-001','AI-FC-002','AI-FC-003']:
                assert any(a['ruleId']==rule and a['disposition']=='OBSERVED' for a in report['assessments']),(name,rule)
        if args.expect_python_rag and report['project']['languages']==['python']:
            for rule in ['AI-PY-001','AI-PY-004','AI-PY-005']:
                assert any(a['ruleId']==rule and a['disposition']=='OBSERVED' for a in report['assessments']),(name,rule)
            assert not any(d['code'] in ['PYTHON_PARSE_FAILED','PYTHON_FLOW_LIMIT','PYTHON_ANALYSIS_LIMIT'] for d in report['diagnostics'])
        assert sarif['runs'][0]['properties']['project']==report['project']
        assert sarif['runs'][0]['properties']['policy']==report['policy']
        assert sarif['runs'][0]['properties']['gateDecision']==report['gateDecision']
        assert sarif['runs'][0]['properties']['securityVerified'] is False
        stable_reports[path]=stable_report(report)
        assert {a['domain'] for a in report['assessments']}=={'L'+str(i) for i in range(1,8)}
        terminal=tool('guardrail_scan_cancel',{'scanId':scanid});assert terminal==s
        row={'name':name,'repository':path,'scanId':scanid,'states':states,'seconds':round(time.monotonic()-t,3),'status':s,'project':report['project'],'runtime':report['runtime'],'dispositions':{d:sum(a['disposition']==d for a in report['assessments']) for d in ['VIOLATED','OBSERVED','UNKNOWN','NOT_APPLICABLE']},'diagnostics':report['diagnostics'],'sourceDigest':report['sourceDigest'],'policy':report['policy'],'gateDecision':report['gateDecision'],'unknownSummary':report['unknownSummary'],'mappingCoverage':report['mappingCoverage'],'artifacts':results['json']['artifacts'],'reportFormatsVerified':True,'terminalStateImmutable':True}
        summary['projects'].append(row)
        print(json.dumps({k:v for k,v in row.items() if k not in ['diagnostics','artifacts']},ensure_ascii=False),flush=True)
    summary['passed']=True
except Exception as error:
    summary['failure']={'type':type(error).__name__,'message':str(error)}
    raise
finally:
    (OUT/'mcp-tool-transcript.json').write_text(json.dumps(transcript,ensure_ascii=False,indent=2)+'\n')
    (OUT/'stable-reports.json').write_text(json.dumps(stable_reports,ensure_ascii=False,indent=2)+'\n')
    (OUT/'summary.json').write_text(json.dumps(summary,ensure_ascii=False,indent=2)+'\n')
    if p.poll() is None:
        p.stdin.close()
        try:p.wait(timeout=10)
        except subprocess.TimeoutExpired:p.terminate();p.wait(timeout=10)
    log.close()
