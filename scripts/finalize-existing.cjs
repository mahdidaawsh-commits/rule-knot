// Read-only recovery of the initial workflow's accepted and rejected receipts.
// This script never signs, deploys, writes, or appeals a transaction.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),assert=require('node:assert/strict');
const {createClient}=require('genlayer-js'),{studionet}=require('genlayer-js/chains');
const root=path.resolve(__dirname,'..'),input=path.resolve(process.argv[2]||path.join(root,'.proof-journal/run-37311744104'));
const load=name=>JSON.parse(fs.readFileSync(path.join(input,name+'.json')));
const digest=bytes=>crypto.createHash('sha256').update(bytes).digest('hex');
const save=(name,value)=>fs.writeFileSync(path.join(root,'proofs',name+'.json'),JSON.stringify(value,null,2)+'\n');
(async()=>{
 const review=load('review'),client=createClient({chain:studionet}),address=review.contract_address;
 assert.equal(await client.request({method:'eth_chainId'}),'0xf22f');
 const code=await client.getContractCode(address);
 assert(Buffer.from(code).equals(fs.readFileSync(path.join(root,'contracts/rule_knot.py'))));
 const state=await client.readContract({address,functionName:'get_state',args:[]});
 assert.deepEqual(state,review.state);
 assert.equal(state.rounds.length,3);
 const rejection=load('exceptions-receipt');
 assert.equal(rejection.result_name,'MAJORITY_DISAGREE');
 for(const name of ['pool-deploy-receipt','feasible-receipt','feasible','conflict-receipt','conflict','review-receipt','review','exceptions-receipt'])save(name,load(name));
 const revision=fs.readFileSync(path.join(root,'config/fixture-revision.txt'),'utf8').trim();
 const sources={};
 for(const name of ['feasible','conflict','review','exceptions'])sources[name]={url:`https://raw.githubusercontent.com/mahdidaawsh-commits/rule-knot/${revision}/records/${name}.md`,sha256:digest(fs.readFileSync(path.join(root,'records',name+'.md')))};
 const transactions=[{label:'pool-deploy',action:'deploy',hash:load('pool-deploy-receipt').hash},...Object.keys(sources).map(label=>({label,action:'inspect',hash:load(label+'-receipt').hash,...(label==='exceptions'?{outcome:'REJECTED'}:{})}))];
 save('exceptions',{network:'studionet',chain_id:61999,contract_address:address,source_sha256:review.source_sha256,fixture_revision:revision,transaction:transactions.at(-1),state,read_only_recovery:true});
 save('deployment',{network:'studionet',chain_id:61999,contract_address:address,source_sha256:digest(Buffer.from(code)),exact_source_match:true,fixture_revision:revision,sources,transactions,read_only_recovery:true,workflow_run:37311744104});
 console.log('Verified deployed source and unchanged state; recovered five finalized receipts without sending transactions.');
})().catch(error=>{console.error(error);process.exitCode=1});
