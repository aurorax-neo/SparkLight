// 固定公开研究环境，绝不代表实际浏览器指纹；所有最终网络操作始终抛错。
var window=globalThis,self=globalThis,global=globalThis,top=globalThis;
var OrigDate=Date;Date=class extends OrigDate{constructor(...args){super(...(args.length?args:[1700000000000]))}static now(){return 1700000000000}};
var seed=123456;Math.random=function(){seed=(Math.imul(seed,1664525)+1013904223)>>>0;return seed/4294967296};
var __sinks=[];
function denied(){throw new Error('OFFLINE_NETWORK_DENIED')}
function store(){var m=new Map();return {getItem:k=>m.get(k)||null,setItem:(k,v)=>m.set(k,String(v)),removeItem:k=>m.delete(k)}}
var location={href:'https://www.douyin.com/',origin:'https://www.douyin.com',hostname:'www.douyin.com',host:'www.douyin.com',protocol:'https:',pathname:'/',search:'',hash:''};
var navigator={userAgent:'offline-dependency-probe',language:'zh-CN',languages:['zh-CN'],sendBeacon:denied};
var screen={width:1280,height:720,availWidth:1280,availHeight:720,colorDepth:24,pixelDepth:24};
var innerWidth=1280,innerHeight=720,outerWidth=1280,outerHeight=720,devicePixelRatio=1;
var performance={now:()=>0},localStorage=store(),sessionStorage=store();
function element(tag='div'){var el={tagName:String(tag).toUpperCase(),style:{},classList:{add(){},remove(){},contains(){return false},toggle(){return false}},setAttribute(k,v){this[k]=v},getAttribute(){return null},appendChild:denied,removeChild(){},getContext:denied,cloneNode(){return element(tag)},addEventListener(){},removeEventListener(){}};if(tag==='a'){var url=new URL(location.href);Object.defineProperty(el,'href',{get:()=>url.href,set:v=>url=new URL(v,location.href)});for(var k of ['hostname','host','pathname','search','hash','protocol','origin'])Object.defineProperty(el,k,{get:()=>url[k],set:v=>url[k]=v});}return el;}
var document={cookie:'',referrer:'',URL:location.href,location,addEventListener(){},removeEventListener(){},createElement:element,getElementsByTagName:()=>[],querySelector:()=>null,documentElement:element(),head:element(),body:element(),createEvent:()=>({initEvent(){},initCustomEvent(){}})};
function XMLHttpRequest(){this.readyState=0;this.status=0;this.responseText='';this.withCredentials=false;}
XMLHttpRequest.prototype={open(method,url){this._method=method;this._url=String(url);this.readyState=1},send(body){__sinks.push({url:this._url,method:this._method,body:typeof body==='string'?body:null});denied()},setRequestHeader(){},addEventListener(){},removeEventListener(){},overrideMimeType(){},getAllResponseHeaders(){return ''},getResponseHeader(){return null},abort(){}};
var fetch=function(url,options){__sinks.push({url:String(url),method:options?.method||'GET',body:options?.body||null});denied()};
var WebSocket=denied;
var setTimeout=()=>1,setInterval=()=>1,requestAnimationFrame=()=>1;
var clearTimeout=()=>{},clearInterval=()=>{},cancelAnimationFrame=()=>{},addEventListener=()=>{},removeEventListener=()=>{};
var console={log(){},warn(){},error(){}};
function offlineCase(code){try{eval(code)}catch(e){if(e.message!=='OFFLINE_NETWORK_DENIED')throw new Error('OFFLINE_CASE_FAILED')}return __sinks;}
