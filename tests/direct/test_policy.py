import ast
import hashlib
import itertools
import json
import re
from pathlib import Path
import pytest

ROOT=Path(__file__).resolve().parents[2]
POLICY=json.loads((ROOT/'config/policy.json').read_text())
DOCS={name:(ROOT/'records'/f'{name}.md').read_bytes() for name in ['feasible','conflict','review','exceptions']}
def rules(name):
    pieces=re.split(r'(?m)^## ([a-z][a-z0-9-]{0,31})\s*$',DOCS[name].decode())
    return list(zip(pieces[1::2],[text.strip() for text in pieces[2::2]]))
def source(name):return f"https://raw.githubusercontent.com/mahdidaawsh-commits/rule-knot/{'a'*40}/records/{name}.md",hashlib.sha256(DOCS[name]).hexdigest()
def report(name):
    verdicts=[]
    for mask in range(8):
        fast,manual,offline=[bool(mask&(1<<i)) for i in range(3)]
        values={'feasible':[manual,not fast or offline,fast or offline],
                'conflict':[manual,not fast or not manual,fast,offline],
                'review':[True if fast else None,not fast],
                'exceptions':[fast or manual,manual or offline,not fast or not offline]}[name]
        verdicts.append(['UNKNOWN' if value is None else ('ALLOW' if value else 'DENY') for value in values])
    return {'tables':[{'id':identity,'verdicts':[row[i] for row in verdicts],'quote':text} for i,(identity,text) in enumerate(rules(name))]}
def mock(vm,name,leader=None,independent=None,anchors=None,changed=None):
    vm.clear_mocks()
    vm.mock_web(re.escape(source(name)[0]),{'status':200,'body':DOCS[name] if changed is None else changed})
    vm.mock_llm(r'.*RULEKNOT-LEADER.*',json.dumps(report(name) if leader is None else leader))
    vm.mock_llm(r'.*RULEKNOT-VALIDATOR.*',json.dumps(report(name) if independent is None else independent))
    vm.mock_llm(r'.*RULEKNOT-ANCHORS.*',json.dumps({'valid':[True]*len(rules(name)) if anchors is None else anchors}))
@pytest.fixture
def checker(direct_deploy):return direct_deploy(str(ROOT/'contracts/rule_knot.py'),json.dumps(POLICY))
def run(c,vm,name):mock(vm,name);c.inspect(*source(name));return c.get_state()['rounds'][-1]['result']

def test_feasible(checker,direct_vm):
    r=run(checker,direct_vm,'feasible')
    assert r['status']=='READY' and r['certain_masks']==[6,7] and r['witness']==6
def test_minimum_core_excludes_irrelevant_clause(checker,direct_vm):
    r=run(checker,direct_vm,'conflict')
    assert r['status']=='CONFLICT' and r['possible_masks']==[]
    assert r['core']==['signoff','fast-no-signoff','expedite']
    assert r['removal_witnesses']==[{'removed':name,'mask':mask,'certain':True} for name,mask in [('signoff',1),('fast-no-signoff',3),('expedite',2)]]
def test_unknown_is_possible_not_certain(checker,direct_vm):
    r=run(checker,direct_vm,'review')
    assert r['status']=='REVIEW' and r['certain_masks']==[] and r['possible_masks']==[0,2,4,6] and r['possible_witness']==0
def test_exception_semantics(checker,direct_vm):
    r=run(checker,direct_vm,'exceptions')
    assert r['certain_masks']==[2,3,6] and r['witness']==2
def test_validator_agrees(checker,direct_vm):
    run(checker,direct_vm,'conflict');assert direct_vm.run_validator() is True
@pytest.mark.parametrize('value',['DENY','UNKNOWN'])
def test_exact_cell_disagreement(checker,direct_vm,value):
    run(checker,direct_vm,'feasible');r=report('feasible');r['tables'][0]['verdicts'][2]=value
    mock(direct_vm,'feasible',independent=r);assert direct_vm.run_validator() is False
def test_validator_anchor_relevance(checker,direct_vm):
    run(checker,direct_vm,'review');mock(direct_vm,'review',anchors=[False,True]);assert direct_vm.run_validator() is False
def test_validator_hash_binding(checker,direct_vm):
    run(checker,direct_vm,'feasible');mock(direct_vm,'feasible',changed=DOCS['feasible']+b'changed');assert direct_vm.run_validator() is False
@pytest.mark.parametrize('kind',['omission','enum','foreign-quote','order'])
def test_malformed_report(checker,direct_vm,kind):
    r=report('feasible')
    if kind=='omission':r['tables'][0]['verdicts'].pop()
    if kind=='enum':r['tables'][0]['verdicts'][0]='YES'
    if kind=='foreign-quote':r['tables'][0]['quote']=r['tables'][1]['quote']
    if kind=='order':r['tables'].reverse()
    mock(direct_vm,'feasible',leader=r)
    with direct_vm.expect_revert():checker.inspect(*source('feasible'))
def test_duplicate_does_not_append(checker,direct_vm):
    run(checker,direct_vm,'feasible')
    with direct_vm.expect_revert('Duplicate record'):checker.inspect(*source('feasible'))
    assert len(checker.get_state()['rounds'])==1
def test_distinct_append_only_batches(checker,direct_vm):
    for name in DOCS:run(checker,direct_vm,name)
    assert len(checker.get_state()['rounds'])==4
@pytest.mark.parametrize('url',['https://example.com/policy.md',f"https://raw.githubusercontent.com/other/rule-knot/{'a'*40}/records/feasible.md"])
def test_publisher_binding(checker,direct_vm,url):
    with direct_vm.expect_revert('pinned publisher'):checker.inspect(url,'a'*64)
def test_leader_hash_mismatch(checker,direct_vm):
    mock(direct_vm,'feasible',changed=DOCS['feasible']+b'changed')
    with direct_vm.expect_revert('commitment mismatch'):checker.inspect(*source('feasible'))
def solver():
    tree=ast.parse((ROOT/'contracts/rule_knot.py').read_text())
    selected=[node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name in ['candidates','choose','analyze']]
    def failure(message):raise AssertionError(message)
    ns={'itertools':itertools,'fail':failure};exec(compile(ast.Module(body=selected,type_ignores=[]),'solver','exec'),ns)
    return ns['analyze']
def test_exhaustive_three_valued_minimum_cores():
    analyze=solver()
    # Independently enumerate all 729 three-clause, two-configuration tables.
    for cells in itertools.product(['ALLOW','DENY','UNKNOWN'],repeat=6):
        tables=[{'id':str(i),'verdicts':list(cells[2*i:2*i+2])} for i in range(3)]
        result=analyze({'tables':tables},2)
        possible=[m for m in range(2) if all(row['verdicts'][m]!='DENY' for row in tables)]
        certain=[m for m in range(2) if all(row['verdicts'][m]=='ALLOW' for row in tables)]
        assert result['possible_masks']==possible and result['certain_masks']==certain
        assert result['status']==('READY' if certain else 'REVIEW' if possible else 'CONFLICT')
        if possible:assert not result['core'];continue
        subsets=[subset for size in range(1,4) for subset in itertools.combinations(range(3),size)]
        conflict=[subset for subset in subsets if all(any(tables[i]['verdicts'][m]=='DENY' for i in subset) for m in range(2))]
        expected=conflict[0]
        assert result['core']==[str(i) for i in expected]
        for witness in result['removal_witnesses']:
            remaining=[i for i in expected if str(i)!=witness['removed']]
            valid=[m for m in range(2) if all(tables[i]['verdicts'][m]!='DENY' for i in remaining)]
            assert witness['mask']==min(valid,key=lambda m:(m.bit_count(),m))
            assert witness['certain']==all(tables[i]['verdicts'][witness['mask']]=='ALLOW' for i in remaining)
