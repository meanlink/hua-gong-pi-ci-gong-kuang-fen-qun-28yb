import {session} from '../stores/session.js';
export async function api(path,options={}){
 const headers={'Content-Type':'application/json',...(session.token?{Authorization:'Bearer '+session.token}:{}),...options.headers};
 const r=await fetch('/api'+path,{...options,headers});
 if(!r.ok){let d=await r.json().catch(()=>({detail:'连接失败，请稍后重试'}));if(r.status===401&&path!='/auth/login'){session.clear();location.hash='#/login';}throw new Error(typeof d.detail==='string'?d.detail:JSON.stringify(d.detail));}
 return r.json();
}
export async function download(id,format){
 const r=await fetch('/api/deliveries/'+id+'/download?format='+format,{headers:{Authorization:'Bearer '+session.token}});
 if(!r.ok)throw new Error('下载失败，请重试');
 const u=URL.createObjectURL(await r.blob()),a=document.createElement('a');a.href=u;a.download='分析归档-'+id+'.'+format;a.click();setTimeout(()=>URL.revokeObjectURL(u),1000);
}
export async function downloadSeal(id,code){
 const r=await fetch('/api/credibility/seals/'+id+'/export',{headers:{Authorization:'Bearer '+session.token}});
 if(!r.ok)throw new Error('封存下载失败，请重试');
 const u=URL.createObjectURL(await r.blob()),a=document.createElement('a');a.href=u;a.download=code+'.seal.json';a.click();setTimeout(()=>URL.revokeObjectURL(u),1000);
}
export async function verifySealFile(file){
 const fd=new FormData();fd.append('file',file);
 const r=await fetch('/api/credibility/seals/verify-upload',{method:'POST',headers:{Authorization:'Bearer '+session.token},body:fd});
 const data=await r.json().catch(()=>({issues:[{type:'tamper',detail:'核验服务无响应'}]}));
 if(!r.ok)throw new Error(data.detail||'核验请求失败');
 return data;
}
