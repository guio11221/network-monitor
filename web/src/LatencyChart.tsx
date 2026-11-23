import React from 'react';
export type Sample = {id:number;checked_at:string;reachable:number;latency_ms:number|null};
export function LatencyChart({samples}:{samples:Sample[]}) {
  const ordered=[...samples].reverse();
  if(!ordered.length) return <div className="empty">Sem medições de latência. Clique em “Medir latência”.</div>;
  const max=Math.max(10,...ordered.map(s=>s.latency_ms??0));
  const width=700,height=145,pad=16;
  const points=ordered.map((s,i)=>({x:pad+(ordered.length===1?0:(i/(ordered.length-1))*(width-pad*2)),y:height-pad-((s.latency_ms??0)/max)*(height-pad*2),s}));
  const lines:string[][]=[];let segment:string[]=[];
  for(const p of points){if(p.s.reachable && p.s.latency_ms!==null)segment.push(`${p.x},${p.y}`);else{if(segment.length)lines.push(segment);segment=[];}}
  if(segment.length)lines.push(segment);
  const uptime=Math.round(ordered.filter(s=>s.reachable).length*100/ordered.length);
  const mean=ordered.filter(s=>s.latency_ms!==null).map(s=>s.latency_ms as number);
  const average=mean.length ? (mean.reduce((a,b)=>a+b,0)/mean.length).toFixed(1):'—';
  return <div className="latency-box"><div className="latency-summary"><strong>Disponibilidade nas amostras: {uptime}%</strong><span>Latência média: {average} ms · {samples.length} medições</span></div>
    <svg className="latency-svg" viewBox={`0 0 ${width} ${height}`} role="img" aria-label="Gráfico de latência histórica">
      {[0,.5,1].map(t=><line key={t} x1={pad} x2={width-pad} y1={pad+t*(height-pad*2)} y2={pad+t*(height-pad*2)} stroke="#e2e8f0" strokeDasharray="4 5"/>)}
      {lines.map((l,i)=><polyline key={i} points={l.join(' ')} fill="none" stroke="#3475ed" strokeWidth="2.5" strokeLinejoin="round"/>)}
      {points.filter(p=>!p.s.reachable).map(p=><circle key={p.s.id} cx={p.x} cy={height-pad} r="3.5" fill="#dc5757"><title>Sem resposta: {new Date(p.s.checked_at).toLocaleString('pt-BR')}</title></circle>)}
      {points.filter(p=>p.s.reachable&&p.s.latency_ms!==null).map(p=><circle key={p.s.id} cx={p.x} cy={p.y} r="2" fill="#3475ed"><title>{p.s.latency_ms} ms · {new Date(p.s.checked_at).toLocaleString('pt-BR')}</title></circle>)}
    </svg><div className="latency-label">Pontos vermelhos: sem resposta ICMP (não necessariamente dispositivo desligado).</div></div>;
}
