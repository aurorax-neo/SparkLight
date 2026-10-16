// 仅研究使用；不进入 Docker 或生产依赖。执行锁定的官方源码而非自写算法。
const fs=require('node:fs'),vm=require('node:vm'),crypto=require('node:crypto'),assert=require('node:assert/strict');
const baseline=JSON.parse(fs.readFileSync('src/douyin/sdk/ticket_input_baseline.json','utf8'));
const parent=fs.readFileSync(process.argv[2]);
const hash=b=>crypto.createHash('sha256').update(b).digest('hex');
assert.equal(hash(parent),baseline.parent_sha256,'官方父资源摘要不符');
const [start,end]=baseline.parent_byte_range;
const fragment=Buffer.concat([parent.subarray(start,end),Buffer.from(';\n')]);
assert.equal(hash(fragment),baseline.fragment_sha256,'官方范围不符');
assert.deepEqual(fragment,fs.readFileSync('src/douyin/sdk/ticket_input.js'),'嵌入片段并非官方原文');
const context=vm.createContext({});vm.runInContext(fragment.toString('utf8'),context,{timeout:1000});
for(const test of baseline.cases){
 const {path,ticket,timestamp}=test.input;
 // 参数也在同一个 realm 中构造，避免 instanceof Array 的跨 realm 差异。
 const args=JSON.stringify([{url:'https://imapi.douyin.com'+path},ticket,path,null,null,timestamp]);
 const result=JSON.parse(vm.runInContext(`JSON.stringify(n6(...${args}))`,context,{timeout:1000}));
 assert.deepEqual(result,test.expected);
}
console.log(JSON.stringify({parent_sha256:hash(parent),fragment_sha256:hash(fragment),cases:baseline.cases.length,matched:true,scope:'official input construction only; no signature, no network'}));
