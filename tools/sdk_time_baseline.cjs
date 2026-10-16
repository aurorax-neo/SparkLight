// 仅离线执行锁定官方时间片段；无网络、账号材料或本地时间回退声明。
const fs=require('node:fs'),vm=require('node:vm'),crypto=require('node:crypto'),assert=require('node:assert/strict');
const parent=fs.readFileSync(process.argv[2]);
const hash=b=>crypto.createHash('sha256').update(b).digest('hex');
assert.equal(hash(parent),'ef38b30991af9aab6f2ff9a849991c38799a9cc5fcedd3ede006a8eeba90995d');
const fragments=[
 {range:[169999,170115],sha256:'4d1d13e6da2c083d6de5686f5f90695d2472321718bbf15fe06e13a98e7f41bd'},
 {range:[170532,171172],sha256:'88ab11b512b4093af0958891658884f4efca19c182a0cbb9b333cb6431cd5d30'}
].map(({range:[a,b],sha256})=>{const x=parent.subarray(a,b);assert.equal(hash(x),sha256);return x.toString('utf8')});
const fixture=JSON.parse(fs.readFileSync('src/douyin/sdk/time_baseline.json','utf8'));
for(const c of fixture.cases){
 const ctx=vm.createContext({mono:c.monotonic_ms,wall:c.wall_ms,Date:{now:()=>c.wall_ms},nu:()=>c.monotonic_ms,nt:(o,k,v)=>(o[k]=v,o)});
 vm.runInContext(`var clock={anchor:{serverEpochSec:1700000000,monotonicMs:1000,wallClockMs:1000000},refreshIntervalMs:3600000};(function(){${fragments.join(';')};}).call(clock);`,ctx,{timeout:1000});
 const out=JSON.parse(vm.runInContext('JSON.stringify({timestamp:clock.getAnchorTimestampSec(clock.anchor),age_ms:clock.getAnchorAgeFields().anchorAgeMs,signable:clock.hasSignableAnchor()})',ctx,{timeout:1000}));
 assert.deepEqual(out,c.expected);
}
console.log(JSON.stringify({official_time_fragments:2,cases:fixture.cases.length,matched:true,network:false,scope:'anchor calculation and expiry only; no credential renewal'}));
