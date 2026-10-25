import type { DiagnosticAccepted, DiagnosticAnalysis, DiagnosticProgressEvent, DiagnosticRun, TestName } from '../types'
const API = import.meta.env.VITE_API_URL ?? 'http://127.0.0.1:8000/api/v1'
async function request<T>(path:string, init?:RequestInit):Promise<T>{
  const response=await fetch(`${API}${path}`,{...init,headers:{'Content-Type':'application/json',...(init?.headers??{})}})
  if(!response.ok){let message=`Request failed (${response.status})`;try{const body=await response.json();message=body.detail??message}catch{};throw new Error(typeof message==='string'?message:JSON.stringify(message))}
  return response.json() as Promise<T>
}
export const runDiagnostics=(target:string,tests:TestName[],port:number,timeout_seconds:number)=>request<DiagnosticAccepted>('/diagnostics',{method:'POST',body:JSON.stringify({target,tests,port,timeout_seconds})})
export const getDiagnostic=(runId:number)=>request<DiagnosticRun>(`/diagnostics/${runId}`)
export const getDiagnosticAnalysis=(runId:number)=>request<DiagnosticAnalysis>(`/diagnostics/${runId}/analysis`)
export async function downloadDiagnosticReport(runId:number):Promise<void>{
  const response=await fetch(`${API.replace(/\/$/,'')}/reports/${runId}`)
  if(!response.ok)throw new Error(`Report download failed (${response.status})`)
  const blob=await response.blob()
  const disposition=response.headers.get('Content-Disposition')??''
  const match=disposition.match(/filename="?([^";]+)"?/i)
  const filename=match?.[1]??`netdoctor-report-${runId}.html`
  const url=URL.createObjectURL(blob)
  const anchor=document.createElement('a');anchor.href=url;anchor.download=filename
  document.body.appendChild(anchor);anchor.click();anchor.remove();URL.revokeObjectURL(url)
}
export const getHistory=(limit=10,offset=0,target?:string,status?:string)=>{
  const params=new URLSearchParams({limit:String(limit),offset:String(offset)})
  if(target)params.set('target',target)
  if(status)params.set('status',status)
  return request<DiagnosticRun[]>(`/history?${params.toString()}`)
}
export const getHistoryDetail=(runId:number)=>request<DiagnosticRun>(`/history/${runId}`)
export function watchDiagnostic(runId:number,onProgress:(event:DiagnosticProgressEvent)=>void,onDisconnect:()=>void,onOpen:()=>void):()=>void{
  const url=new URL(API,window.location.href)
  url.protocol=url.protocol==='https:'?'wss:':'ws:'
  url.pathname=`${url.pathname.replace(/\/$/,'')}/diagnostics/${runId}/ws`
  const socket=new WebSocket(url)
  let closed=false
  let reportedDisconnect=false
  socket.onopen=()=>{if(!closed)onOpen()}
  socket.onmessage=(message)=>{
    try{onProgress(JSON.parse(message.data) as DiagnosticProgressEvent)}catch{if(!reportedDisconnect){reportedDisconnect=true;onDisconnect()}}
  }
  const disconnected=()=>{if(!closed&&!reportedDisconnect){reportedDisconnect=true;onDisconnect()}}
  socket.onerror=disconnected
  socket.onclose=disconnected
  return ()=>{closed=true;socket.close()}
}
