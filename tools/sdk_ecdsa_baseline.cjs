// 仅离线研究：公开测试密钥，执行锁定官方 ECDSA 片段；不调用账号、网络或完整 SDK。
const fs = require('node:fs');
const vm = require('node:vm');
const crypto = require('node:crypto');
const assert = require('node:assert/strict');
const hash = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
const parentHash = 'ef38b30991af9aab6f2ff9a849991c38799a9cc5fcedd3ede006a8eeba90995d';
const specs = [
  {range:[35909,36314], sha256:'117aaabc7db5d9a6edbdec13e3e6e2f2db45180feaa9dcac916c9f29ca7ff5d6'},
  {range:[36984,37526], sha256:'9c2d559b1c55510aafe1d5a7725fd3dfe3a999d0193389aa18b7412b00d0bb28'},
  {range:[41200,41991], sha256:'e654185f238a0a1c4bad6af727774796416120d78fff7faba987537a27bdf67b'},
];
const parent = fs.readFileSync(process.argv[2]);
assert.equal(hash(parent), parentHash, '官方父资源摘要不符');
const fragments = specs.map(({range:[start,end],sha256}) => {
  const bytes=parent.subarray(start,end);
  assert.equal(hash(bytes),sha256,'官方片段摘要不符');
  return bytes.toString('utf8');
});
const fixturePath='src/douyin/sdk/ecdsa_offline_baseline.json';
const inputs=JSON.parse(fs.readFileSync('src/douyin/sdk/ticket_input_baseline.json','utf8'));
const mode=process.argv[3];
assert.ok(mode==='--generate-public-fixture'||mode==='--check');
// 标准测试标量 1，仅用于离线互操作；绝不能作为实际账号密钥。
const scalar=Buffer.alloc(32); scalar[31]=1;
const ec=crypto.createECDH('prime256v1'); ec.setPrivateKey(scalar);
const point=ec.getPublicKey();
const privateKey=crypto.createPrivateKey({key:{kty:'EC',crv:'P-256',d:scalar.toString('base64url'),x:point.subarray(1,33).toString('base64url'),y:point.subarray(33).toString('base64url')},format:'jwk'});
const publicKey=crypto.createPublicKey(privateKey);
const pem=privateKey.export({type:'pkcs8',format:'pem'});
const context=vm.createContext({window:{atob,crypto:crypto.webcrypto},TextEncoder,w:{wb:bytes=>Buffer.from(bytes).toString('hex')}});
vm.runInContext(`${fragments[0]}\n${fragments[1]}\nvar ${fragments[2]};`,context,{timeout:1000});
async function officialSign(data){
  context.testPem=pem; context.testData=data;
  const output=await vm.runInContext('ey(testPem,testData)',context,{timeout:1000});
  const der=Buffer.from(output.hex,'hex');
  assert.deepEqual(der,Buffer.from(output.buffer));
  assert.ok(crypto.verify('sha256',Buffer.from(data),publicKey,der));
  assert.ok(!crypto.verify('sha256',Buffer.from(data+'!'),publicKey,der));
  return der;
}
async function main(){
  const cases=[];
  for(const test of inputs.cases){
    const der=await officialSign(test.expected.sign_data);
    cases.push({input:test.input,sign_data:test.expected.sign_data,official_signature_der_base64:der.toString('base64')});
  }
  const fixture={scope:'PUBLIC OFFLINE TEST KEY ONLY; official ECDSA fragment, not complete SDK or server acceptance',parent_sha256:parentHash,fragments:specs,test_scalar_hex:scalar.toString('hex'),public_key_sec1_base64:point.toString('base64'),public_key_spki_base64:publicKey.export({type:'spki',format:'der'}).toString('base64'),cases};
  if(mode==='--generate-public-fixture') fs.writeFileSync(fixturePath,JSON.stringify(fixture,null,2)+'\n',{flag:'wx'});
  else {
    const saved=JSON.parse(fs.readFileSync(fixturePath,'utf8'));
    for(const k of ['scope','parent_sha256','fragments','test_scalar_hex','public_key_sec1_base64','public_key_spki_base64'])assert.deepEqual(saved[k],fixture[k]);
    assert.equal(saved.cases.length,cases.length);
    for(let i=0;i<cases.length;i++){
      const c=saved.cases[i]; assert.deepEqual(c.input,cases[i].input); assert.equal(c.sign_data,cases[i].sign_data);
      assert.ok(crypto.verify('sha256',Buffer.from(c.sign_data),publicKey,Buffer.from(c.official_signature_der_base64,'base64')));
      assert.ok(c.rust_signature_der_base64,'缺少 Rust 交叉签名');
      assert.ok(crypto.verify('sha256',Buffer.from(c.sign_data),publicKey,Buffer.from(c.rust_signature_der_base64,'base64')));
      assert.ok(!crypto.verify('sha256',Buffer.from(c.sign_data+'!'),publicKey,Buffer.from(c.rust_signature_der_base64,'base64')));
    }
  }
  console.log(JSON.stringify({parent_sha256:parentHash,official_fragments:specs.length,cases:cases.length,official_sign_node_verify:true,rust_sign_node_verify:mode==='--check',network:false,production_enabled:false}));
}
main().catch(()=>{console.error('离线 ECDSA 基准失败（不输出密钥或签名）');process.exitCode=1;});
