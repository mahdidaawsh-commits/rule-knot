const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),assert=require('node:assert/strict');
const root=path.resolve(__dirname,'..'),digest=bytes=>crypto.createHash('sha256').update(bytes).digest('hex');
const read=name=>JSON.parse(fs.readFileSync(path.join(root,'proofs',name+'.json')));
const deployment=read('deployment');
assert.equal(deployment.chain_id,61999);
assert.equal(deployment.source_sha256,digest(fs.readFileSync(path.join(root,'contracts/rule_knot.py'))));
assert.equal(deployment.exact_source_match,true);
assert.equal(deployment.transactions.length,5);
const choose=masks=>masks.length?masks.slice().sort((a,b)=>a.toString(2).replaceAll('0','').length-b.toString(2).replaceAll('0','').length||a-b)[0]:null;
function expected(name,mask){
 const f=!!(mask&1),m=!!(mask&2),o=!!(mask&4);
 const values={feasible:[m,!f||o,f||o],conflict:[m,!f||!m,f,o],review:[f?true:null,!f],exceptions:[f||m,m||o,!f||!o]}[name];
 return values.map(value=>value===null?'UNKNOWN':value?'ALLOW':'DENY');
}
function subsets(n){
 const rows=[];
 function visit(start,remaining,current){if(!remaining){rows.push(current);return;}for(let i=start;i<n;i++)visit(i+1,remaining-1,[...current,i]);}
 for(let size=1;size<=n;size++)visit(0,size,[]);
 return rows;
}
for(const [index,tx] of deployment.transactions.entries()){
 const receipt=read(tx.label+'-receipt');
 assert.equal(receipt.hash,tx.hash);
 assert.equal(receipt.status_name||receipt.statusName,'FINALIZED');
 assert.equal(receipt.result_name,'MAJORITY_AGREE');
 assert(['SUCCESS','FINISHED_WITH_RETURN'].includes(receipt.txExecutionResultName||receipt.consensus_data.leader_receipt[0].execution_result));
 assert(Object.values(receipt.consensus_data.votes).filter(value=>value==='agree').length>=3);
 if(tx.action==='deploy')continue;
 assert.equal(tx.action,'inspect');
 const proof=read(tx.label),state=proof.state;
 assert.equal(state.rounds.length,index);
 assert.deepEqual(state.policy,JSON.parse(fs.readFileSync(path.join(root,'config/policy.json'))));
 assert.equal(proof.contract_address,deployment.contract_address);
 assert.equal(proof.source_sha256,deployment.source_sha256);
 assert.equal(receipt.to_address.toLowerCase(),deployment.contract_address.toLowerCase());
 const calldata=receipt.data.calldata.readable;
 assert(calldata.includes(state.rounds.at(-1).url));assert(calldata.includes(state.rounds.at(-1).sha256));
 for(const row of state.rounds){
  const name=new URL(row.url).pathname.split('/').pop().replace('.md','');
  const body=fs.readFileSync(path.join(root,'records',name+'.md'));
  assert.equal(digest(body),row.sha256);
  assert.equal(row.url,`https://raw.githubusercontent.com/${state.policy.source_repository}/${deployment.fixture_revision}/records/${name}.md`);
  const pieces=body.toString().split(/^## ([a-z][a-z0-9-]{0,31})\s*$/m);
  const ids=pieces.filter((_,i)=>i%2===1),tables=row.report.tables;
  assert.deepEqual(tables.map(item=>item.id),ids);
  for(const [i,table] of tables.entries()){
   assert(pieces[2*i+2].includes(table.quote)&&table.quote.length>=12);
   assert.equal(table.verdicts.length,8);
   assert.deepEqual(table.verdicts,Array.from({length:8},(_,mask)=>expected(name,mask)[i]));
  }
  const masks=Array.from({length:8},(_,i)=>i),r=row.result;
  const possible=masks.filter(mask=>tables.every(table=>table.verdicts[mask]!=='DENY'));
  const certain=masks.filter(mask=>tables.every(table=>table.verdicts[mask]==='ALLOW'));
  assert.deepEqual(r.certain_masks,certain);assert.deepEqual(r.possible_masks,possible);
  assert.equal(r.witness,choose(certain));assert.equal(r.possible_witness,choose(possible));
  assert.equal(r.status,certain.length?'READY':possible.length?'REVIEW':'CONFLICT');
  if(possible.length){assert.deepEqual(r.core,[]);assert.deepEqual(r.removal_witnesses,[]);continue;}
  const core=subsets(tables.length).find(indices=>masks.every(mask=>indices.some(i=>tables[i].verdicts[mask]==='DENY')));
  assert.deepEqual(r.core,core.map(i=>tables[i].id));
  assert.deepEqual(r.removal_witnesses,core.map(removed=>{
   const rest=core.filter(i=>i!==removed),valid=masks.filter(mask=>rest.every(i=>tables[i].verdicts[mask]!=='DENY')),mask=choose(valid);
   assert.notEqual(mask,null);
   return {removed:tables[removed].id,mask,certain:rest.every(i=>tables[i].verdicts[mask]==='ALLOW')};
  }));
 }
 console.log('VERIFIED',tx.label,state.rounds.at(-1).result.status);
}
console.log('Verified five finalized receipts, full semantic tables and independently enumerated minimum conflict cores.');
