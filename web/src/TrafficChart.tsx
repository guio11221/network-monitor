import React from 'react';
export type TrafficPoint = {id:number;adapter:string;sampled_at:string;download_bps:number;upload_bps:number};
export function TrafficChart({samples,adapter}:{samples:TrafficPoint[];adapter:string}) {
  const data=samples.filter(s=>s.adapter===adapter).slice(0,60).reverse();
  if(data.length<2)return <div className="empty">Aguardando pelo menos duas amostras de tráfego (15 segundos entre coletas).</div>;
  const width=700,height=190,padding=24;
  const max=Math.max(1,...data.flatMap(x=>[x.download_bps,x.upload_bps]));
  const points=(key:'download_bps'|'upload_bps')=>data.map((x,i)=>{
    const px=padding+i*(width-padding*2)/Math.max(data.length-1,1);
    const py=height-padding-(x[key]/max)*(height-padding*2);
    return `${px.toFixed(1)},${py.toFixed(1)}`;
  }).join(' ');
  const format=(bps:number)=>bps>=1e6?`${(bps/1e6).toFixed(2)} Mbps`:bps>=1e3?`${(bps/1e3).toFixed(1)} Kbps`:`${bps} bps`;
  const last=data[data.length-1]!;
  return <div className="chart-wrapper"><div className="traffic-legend"><span>Download <strong>{format(last.download_bps)}</strong></span><span>Upload <strong>{format(last.upload_bps)}</strong></span><span>Pico: {format(max)}</span></div>
    <svg className="traffic-chart" viewBox={`0 0 ${width} ${height}`} role="img" aria-label={`Tráfego do adaptador ${adapter}, download e upload em bits por segundo`}>
      {[0,.25,.5,.75,1].map(p=><line key={p} x1={padding} x2={width-padding} y1={height-padding-p*(height-2*padding)} y2={height-padding-p*(height-2*padding)} stroke="currentColor" opacity=".1"/>) }
      <polyline points={points('download_bps')} fill="none" stroke="#16a3ff" strokeWidth="2.8" strokeLinejoin="round"/>
      <polyline points={points('upload_bps')} fill="none" stroke="#22c55e" strokeWidth="2.8" strokeLinejoin="round"/>
    </svg><div className="chart-foot"><span>{new Date(data[0]!.sampled_at).toLocaleTimeString('pt-BR')}</span><span>{new Date(last.sampled_at).toLocaleTimeString('pt-BR')}</span></div>
  </div>;
}
