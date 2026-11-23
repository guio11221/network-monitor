import React from 'react';
import { CircleHelp, Monitor, Router, Wifi } from 'lucide-react';

type MapDevice={id:string;ip:string;name:string|null;hostname:string|null;status:'online'|'observed'|'offline';kind:string;trusted:number};
export function NetworkMap({devices, gateway, onSelect}:{devices:MapDevice[];gateway:string|null;onSelect:(id:string)=>void}) {
  const [showOffline,setShowOffline]=React.useState(false);
  const visible=devices.filter(d=>showOffline||d.status!=='offline').slice(0,60);
  const cx=480,cy=295,radius=220;
  const occupied=visible.map((d,index)=>{
    const a=(index/Math.max(visible.length,1))*Math.PI*2-Math.PI/2;
    return {d,x:cx+Math.cos(a)*radius,y:cy+Math.sin(a)*radius};
  });
  return <div className="topology-container">
    <div className="map-toolbar"><span>Mapa lógico baseado nos dispositivos descobertos; as linhas não representam cabos ou conexões reais.</span><label><input type="checkbox" checked={showOffline} onChange={e=>setShowOffline(e.target.checked)}/> Incluir offline</label></div>
    {visible.length===0 ? <div className="empty">Nenhum dispositivo no filtro. Execute uma descoberta de rede.</div> : <div className="map-scroll"><svg role="img" aria-label="Representação lógica dos dispositivos em torno da rede selecionada" viewBox="0 0 960 590" className="network-map">
      <circle cx={cx} cy={cy} r={radius} fill="none" stroke="#e2e9f5" strokeDasharray="4 9"/>
      {occupied.map(({d,x,y})=><line key={`line-${d.id}`} x1={cx} y1={cy} x2={x} y2={y} stroke={d.status==='offline'?'#d8e0eb':'#abc9ed'} strokeWidth="2" strokeDasharray="6 6"/>)}
      <circle cx={cx} cy={cy} r="56" fill="#e8f0ff" stroke="#4c79d4" strokeWidth="2"/>
      <g transform={`translate(${cx-16},${cy-27})`}><Router size={32} color="#2e61b7"/></g>
      <text x={cx} y={cy+14} textAnchor="middle" fontSize="12" fontWeight="700" fill="#31558b">Rede local</text>
      <text x={cx} y={cy+30} textAnchor="middle" fontSize="10" fill="#637b9d">{gateway ?? 'Gateway não identificado'}</text>
      {occupied.map(({d,x,y})=><g key={d.id} tabIndex={0} role="button" aria-label={`Abrir detalhes de ${d.name||d.hostname||d.ip}`} onClick={()=>onSelect(d.id)} onKeyDown={e=>{if(e.key==='Enter'||e.key===' '){e.preventDefault();onSelect(d.id);}}} className="map-node">
        <circle cx={x} cy={y} r="29" fill={d.status==='offline'?'#e8edf4':d.trusted?'#e3f9ee':'#fff4df'} stroke={d.status==='offline'?'#abb8c9':d.trusted?'#1baf72':'#e5a83b'} strokeWidth="2"/>
        <g transform={`translate(${x-12},${y-13})`}>
          {d.kind==='router'?<Router size={24} color="#405671"/>:d.kind==='unknown'?<CircleHelp size={24} color="#405671"/>:d.kind==='iot'||d.kind==='phone'?<Wifi size={24} color="#405671"/>:<Monitor size={24} color="#405671"/>}
        </g>
        <text x={x} y={y+42} textAnchor="middle" fontSize="11" fontWeight="700" fill="#354960">{(d.name||d.hostname||d.ip).slice(0,21)}</text>
        <text x={x} y={y+54} textAnchor="middle" fontSize="10" fill="#788ba4">{d.ip}</text>
        <title>{`${d.name||d.hostname||d.ip} - ${d.status}`}</title>
      </g>)}
    </svg></div>}
    {devices.filter(d=>showOffline||d.status!=='offline').length>60 && <div className="integration-note">Mapa limitado aos primeiros 60 dispositivos; o inventário mostra todos.</div>}
  </div>;
}
