// 研究阶段执行原始官方 SDK，所有网络调用拒绝，环境替身只用于发现依赖，不构成签名等价证明。
const vm=require('node:vm'),fs=require('node:fs'),crypto=require('node:crypto');
const manifest=JSON.parse(fs.readFileSync('src/douyin/sdk/manifest.json','utf8'));
for(const file of process.argv.slice(2)){
 const source=fs.readFileSync(file);const spec=manifest.resources.find(r=>r.name===file.split('/').pop());
 if(!spec||source.length!==spec.size||crypto.createHash('sha256').update(source).digest('hex')!==spec.sha256)throw Error('resource integrity mismatch');
 const events=[];const denied=name=>()=>{events.push(name);throw Error('DENIED:'+name)};
 const storage=new Map();const store={getItem:k=>storage.get(k)||null,setItem:(k,v)=>storage.set(k,String(v)),removeItem:k=>storage.delete(k)};
 class XHR{open(method,url){events.push('network:'+method+':'+String(url).split('?')[0]);throw Error('DENIED:network')}send(){throw Error('DENIED:network')}setRequestHeader(){}addEventListener(){}removeEventListener(){}}
 const missing=[];const observed=(obj,name)=>new Proxy(obj,{get(target,key,receiver){if(typeof key==='string' && !(key in target) && missing.length<50)missing.push(name+'.'+key);return Reflect.get(target,key,receiver)}});
 const element=()=>observed({style:{},setAttribute(){},getAttribute(){return null},appendChild:denied('DOM:appendChild'),getContext:denied('DOM:canvas'),cloneNode(){return element()}},'element');
 const ctx={Request,Headers,Response,URL,URLSearchParams,TextEncoder,TextDecoder,atob,btoa,console:{log(){},warn(){},error(){}},location:{href:'https://www.douyin.com/',origin:'https://www.douyin.com',hostname:'www.douyin.com',protocol:'https:',pathname:'/'},navigator:{userAgent:'offline-dependency-probe',language:'zh-CN',languages:['zh-CN']},performance:{now:()=>0},localStorage:store,sessionStorage:store,fetch:denied('network:fetch'),XMLHttpRequest:XHR,setTimeout:()=>{events.push('timer:deferred');return 1},setInterval:()=>{events.push('timer:deferred');return 1},clearTimeout(){},clearInterval(){},addEventListener(){},removeEventListener(){}};
 ctx.window=ctx;ctx.self=ctx;ctx.global=ctx;ctx.document={cookie:'',referrer:'',URL:ctx.location.href,location:ctx.location,addEventListener(){},removeEventListener(){},createElement:()=>element(),getElementsByTagName:()=>[],querySelector:()=>null,documentElement:element(),head:element(),body:element()};
 ctx.navigator=observed(ctx.navigator,'navigator');ctx.document=observed(ctx.document,'document');
 ctx.document.createEvent=()=>({initEvent(){},initCustomEvent(){}});
 const previousCreateElement=ctx.document.createElement;ctx.document.createElement=()=>{const el=previousCreateElement();el.classList={add(){},remove(){},contains(){return false},toggle(){return false}};return el};
 const context=vm.createContext(ctx);let result={file:spec.name,stage:'load'};
 try{vm.runInContext(source.toString('utf8'),context,{timeout:5000});result.outcome='loaded';if(ctx.byted_acrawler?.frontierSign){result.stage='frontierSign';const output=vm.runInContext('byted_acrawler.frontierSign({})',context,{timeout:2000});result.outputKeys=Object.keys(output||{});result.outputTypes=Object.fromEntries(Object.entries(output||{}).map(([k,v])=>[k,typeof v]));result.stage='init';vm.runInContext('byted_acrawler.init({aid:6383})',context,{timeout:5000});result.outcome='init returned (no parity claim)';}else if(ctx.bdms?.init){result.stage='init';vm.runInContext('bdms.init({aid:6383})',context,{timeout:5000});result.outcome='init returned (no parity claim)';}}
 catch(e){result.outcome='blocked';result.error=String(e.message).replace(/https?:\/\/[^\s]+/g,'[url]').slice(0,180);result.stackLocations=String(e.stack).split('\n').filter(s=>s.includes('evalmachine')).map(s=>s.slice(0,150)).slice(0,4)}
 result.events=events.slice(0,30);result.missingHostProperties=missing;result.production_enabled=false;console.log(JSON.stringify(result));
}
