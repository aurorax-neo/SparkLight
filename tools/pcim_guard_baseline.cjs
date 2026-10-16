// 仅公开离线向量。不给 VM 网络、文件、账号或进程能力。
const fs=require('node:fs'),crypto=require('node:crypto'),vm=require('node:vm');
const ts=require('../frontend/node_modules/typescript');
const [sourcePath,outputPath,extractPath]=process.argv.slice(2);
if(!sourcePath||!outputPath||!extractPath)throw Error('source output extract required');
const raw=fs.readFileSync(sourcePath),digest=crypto.createHash('sha256').update(raw).digest('hex');
if(digest!=='19584d9b6099b1eb538cb8b30695d47eedf86f2358b03a9f29c3d1de7db851f3')throw Error('unrecognized public artifact');
const source=raw.toString('utf8'),tree=ts.createSourceFile('pcim.js',source,ts.ScriptTarget.Latest,true,ts.ScriptKind.JS),wanted=new Set(['rP','r_','rw','rk','rS','rT']),found={};
function visit(n){if(ts.isVariableDeclaration(n)&&wanted.has(n.name.getText(tree))&&n.initializer){const name=n.name.getText(tree);if(found[name])throw Error('ambiguous '+name);found[name]={code:n.initializer.getText(tree),offset:n.initializer.getStart(tree)}}ts.forEachChild(n,visit)}visit(tree);
if(Object.keys(found).length!==wanted.size)throw Error('missing function');
const declarations=[...wanted].map(n=>'const '+n+'='+found[n].code+';').join('\n');
fs.writeFileSync(extractPath,'// Derived pure functions from SHA256 '+digest+'; not standalone full SDK.\n'+declarations+'\n');
const scalar=Buffer.alloc(32,1),serverScalar=Buffer.alloc(32,2);
function pair(s){const e=crypto.createECDH('prime256v1');e.setPrivateKey(s);const pub=e.getPublicKey(null,'uncompressed');const jwk={kty:'EC',crv:'P-256',x:pub.subarray(1,33).toString('base64url'),y:pub.subarray(33).toString('base64url'),d:s.toString('base64url')};const priv=crypto.createPrivateKey({key:jwk,format:'jwk'});return {e,pub,priv,spki:crypto.createPublicKey(priv).export({type:'spki',format:'der'})}}
const key=pair(scalar),server=pair(serverScalar),timestamp=1700000001,path='/v1/message/send',ticket='offline-ticket';
const shared=key.e.computeSecret(server.pub),derived=Buffer.from(crypto.hkdfSync('sha256',shared,Buffer.alloc(0),Buffer.alloc(0),32));
const context=vm.createContext({}, {codeGeneration:{strings:false,wasm:false}});
vm.runInContext('const s={V0:"v0",V1:"v1",V2:"v2"},a={ECDSA:"ecdsa",HMAC:"hmac"}; const NativeDate=Date; Date=class extends NativeDate {constructor(...args){super(...(args.length?args:[1700000001000]))} static now(){return 1700000001000}};'+declarations,context,{timeout:1000});
const input=vm.runInContext('rP({url:"https://imapi.douyin.com/v1/message/send"},"offline-ticket","/v1/message/send",[],{})',context,{timeout:1000});
const cases=[];
for(const prefix of ['ts.1','ts.2'])for(const mode of ['ecdsa','hmac']){
 const signature=mode==='hmac'?crypto.createHmac('sha256',derived).update(input.sign_data).digest('base64'):crypto.sign('sha256',Buffer.from(input.sign_data),key.priv).toString('base64');
 const tsSign=prefix+'.offline';
 const selected=vm.runInContext('rT('+JSON.stringify({tsSign,signType:'pubKey',b64PubKey:key.pub.toString('base64'),algoType:mode})+')',context,{timeout:1000});
 const expectedMarker='D={ts_sign:h,req_content:r||e||p,req_sign:g,timestamp:n||Math.floor(new Date().getTime()/1e3)}';
 if(!source.includes(expectedMarker))throw Error('client-data source changed');
 const payload=vm.runInNewContext('({ts_sign:h,req_content:r||e||p,req_sign:g,timestamp:n||Math.floor(new Date().getTime()/1e3)})',{h:tsSign,r:input.req_content,e:input.sign_data,p:'',g:signature,n:timestamp},{timeout:1000});
 cases.push({mode,ts_sign:tsSign,input,signature_base64:signature,client_data_base64:Buffer.from(JSON.stringify(payload)).toString('base64'),headers:{...selected,'bd-ticket-guard-version':2}});
}
const result={source_sha256:digest,authority:'extracted official pure input/header/payload functions; Node crypto arithmetic baseline; not live authorization',offsets:Object.fromEntries(Object.entries(found).map(([n,v])=>[n,v.offset])),test_only_scalar_hex:scalar.toString('hex'),public_key_sec1_base64:key.pub.toString('base64'),server_public_spki_base64:server.spki.toString('base64'),timestamp,ticket,path,cases};
fs.writeFileSync(outputPath,JSON.stringify(result,null,2)+'\n');console.log(JSON.stringify({cases:cases.length,source_sha256:digest,network_requests:0,private_account_material:0}));
