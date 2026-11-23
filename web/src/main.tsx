import React from 'react';
import { createRoot } from 'react-dom/client';
import { Activity, ArrowDownUp, Cable, Camera, CircleHelp, Clock3, Monitor, Network, Pencil, Printer, RadioTower, RefreshCw, Router, Search, ShieldCheck, Smartphone, Tv, Wifi } from 'lucide-react';
import './styles.css';
import { LatencyChart, type Sample } from './LatencyChart.js';
import { NetworkMap } from './NetworkMap.js';
import { TrafficChart, type TrafficPoint } from './TrafficChart.js';

type Status = 'online' | 'observed' | 'offline';
type Device = { id: string; network_id: string; ip: string; mac: string | null; name: string | null; hostname: string | null; vendor: string | null; kind: string; ports: {port:number;service:string}[]; ports_scanned_at:string|null; status: Status; first_seen: string; last_seen: string; trusted:number;notes:string;tags:string[] };
type NetworkInterface = { id: string; name: string; address: string; cidr: string; supported: boolean; totalHosts: number };
type LogEvent = { id: number; device_id: string; ip: string; kind: string; created_at: string };
type Diagnostics = {checkedAt:string;gateway:{ip:string|null;probe:{reachable:boolean;latencyMs:number|null}|null};dns:{ok:boolean;address:string|null;error:string|null};internet:{ok:boolean;status:number|null;error:string|null}};
type Availability = {deviceId:string;ip:string;name:string|null;samples:number;responsive:number;uptimePct:number;averageLatencyMs:number|null};
type Preferences={scanIntervalSeconds:number;probeIntervalSeconds:number};
type State = {preferences:Preferences; traffic:TrafficPoint[]; availability:Availability[];telegramConfigured:boolean;trafficError:string|null; interfaces: NetworkInterface[]; selectedId: string | null; devices: Device[]; events: LogEvent[]; scanning: boolean; portBusy:boolean; probing:boolean; diagnosticsBusy:boolean; diagnostics:Diagnostics|null; mode:'nmap'|'fallback'; nmapInstalled:boolean; lastScan: string | null; error: string | null; stats: { total: number; online: number; observed: number; offline: number } };
const emptyState: State = { preferences:{scanIntervalSeconds:60,probeIntervalSeconds:300}, traffic:[],availability:[],telegramConfigured:false,trafficError:null, interfaces:[], selectedId:null, devices:[], events:[], scanning:false,portBusy:false,probing:false,diagnosticsBusy:false,diagnostics:null,mode:'fallback',nmapInstalled:false,lastScan:null, error:null, stats:{total:0,online:0,observed:0,offline:0} };
function dateTime(date: string | null): string { return date ? new Date(date).toLocaleString('pt-BR') : '—'; }
function typeIcon(kind: string) {
  if (kind === 'router') return <Router size={19}/>;
  if (kind === 'phone') return <Smartphone size={19}/>;
  if (kind === 'printer') return <Printer size={19}/>;
  if (kind === 'tv') return <Tv size={19}/>;
  if (kind === 'camera') return <Camera size={19}/>;
  if (kind === 'iot') return <Wifi size={19}/>;
  return <Monitor size={19}/>;
}
const kindLabel: Record<string,string> = {router:'Roteador',computer:'Computador',phone:'Celular',printer:'Impressora',tv:'TV / mídia',camera:'Câmera',iot:'IoT',unknown:'Desconhecido'};
async function request(url: string, method: string, body?: unknown): Promise<void> {
  const response = await fetch(url, { method, headers:{'Content-Type':'application/json'}, body:body === undefined ? undefined : JSON.stringify(body) });
  if (!response.ok) { const data = await response.json().catch(() => ({})); throw new Error(data.error || `Erro HTTP ${response.status}`); }
}
function App() {
  const [data, setData] = React.useState<State>(emptyState);
  const [query, setQuery] = React.useState('');
  const [filter, setFilter] = React.useState<'all'|Status>('all');
  const [connected, setConnected] = React.useState(false);
  const [actionError, setActionError] = React.useState<string|null>(null);
  const [scanningDevice, setScanningDevice] = React.useState<string|null>(null);
  const [chartDevice,setChartDevice] = React.useState<string|null>(null);
  const [samples,setSamples] = React.useState<Sample[]>([]);
  const [alertsOnly,setAlertsOnly] = React.useState(false);
  const [adapter,setAdapter] = React.useState('');
  const [authorized,setAuthorized] = React.useState(false);
  const [checkingLogin,setCheckingLogin] = React.useState(true);
  const [loginError,setLoginError] = React.useState('');
  const [password,setPassword] = React.useState('');
  const [tab,setTab] = React.useState<'overview'|'map'|'settings'>('overview');
  const [settings,setSettings] = React.useState<Preferences>({scanIntervalSeconds:60,probeIntervalSeconds:300});
  const [editor,setEditor] = React.useState<string|null>(null);
  const [notes,setNotes] = React.useState('');
  const [tags,setTags] = React.useState('');
  const [oldPassword,setOldPassword] = React.useState('');
  const [newPassword,setNewPassword] = React.useState('');
  React.useEffect(()=>{setSettings(data.preferences);},[data.preferences.scanIntervalSeconds,data.preferences.probeIntervalSeconds]);
  React.useEffect(()=>{fetch('/api/state').then(r=>{if(r.status===401)return null;if(!r.ok)throw new Error();return r.json();}).then(s=>{setAuthorized(!!s);if(s)setData(s);}).catch(()=>{}).finally(()=>setCheckingLogin(false));},[]);
  const login=async(e:React.FormEvent)=>{
    e.preventDefault();setLoginError('');
    try {
      const response=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:'admin',password})});
      if(!response.ok){const body=await response.json();throw new Error(body.error||'Falha de autenticação');}
      const state=await fetch('/api/state');if(!state.ok)throw new Error('Falha ao carregar a sessão');
      setData(await state.json());setAuthorized(true);setPassword('');
    }catch(e){setLoginError(e instanceof Error?e.message:String(e));}
  };
  const logout=async()=>{await fetch('/api/logout',{method:'POST'});setAuthorized(false);setData(emptyState);};
  React.useEffect(() => {
    let closed = false;
    let socket: WebSocket | null = null;
    let retry: ReturnType<typeof setTimeout> | undefined;
    const connect = () => {
      if (closed || !authorized) return;
      socket = new WebSocket(`${location.protocol === 'https:' ? 'wss' : 'ws'}://${location.host}/ws`);
      socket.onopen = () => { if (!closed) setConnected(true); };
      socket.onmessage = event => {
        try { const message = JSON.parse(event.data); if (message.type === 'snapshot' && !closed) setData(message.payload); } catch { /* ignora payload inválido */ }
      };
      socket.onclose = () => { if (!closed) { setConnected(false); retry = setTimeout(connect, 2500); } };
      socket.onerror = () => socket?.close();
    };
    if(!authorized)return;
    void fetch('/api/state').then(r => {if(r.status===401){setAuthorized(false);throw new Error('Sessão expirada');}return r.json();}).then(s => { if (!closed) setData(s); }).catch(() => {});
    connect();
    return () => { closed = true; if (retry) clearTimeout(retry); socket?.close(); };
  }, [authorized]);
  const selected = data.interfaces.find(n => n.id === data.selectedId);
  const adapters = [...new Set(data.traffic.map(x=>x.adapter))];
  const activeAdapter=adapters.includes(adapter)?adapter:(adapters.find(x=>x===selected?.name) || adapters[0] || '');
  const unknownCount=data.devices.filter(d=>!d.trusted && d.status!=='offline').length;
  React.useEffect(()=>{if(!chartDevice){setSamples([]);return;} let disposed=false;fetch(`/api/devices/${encodeURIComponent(chartDevice)}/probes`).then(r=>r.json()).then(r=>{if(!disposed)setSamples(r.samples||[]);}).catch(()=>{});return()=>{disposed=true;};},[chartDevice,data.probing]);
  const visible = data.devices.filter(d => {
    const text = `${d.name||''} ${d.hostname||''} ${d.vendor||''} ${d.kind} ${d.ip} ${d.mac||''} ${d.ports.map(p=>p.port).join(' ')} ${(d.tags||[]).join(' ')} ${d.notes||''}`.toLowerCase();
    return text.includes(query.toLowerCase()) && (filter === 'all' || d.status === filter) && (!alertsOnly || (!d.trusted && d.status !== 'offline'));
  });
  const act = async (fn: () => Promise<void>) => { setActionError(null); try { await fn(); } catch (e) { setActionError(e instanceof Error ? e.message : String(e)); } };
  const rename = (device: Device) => {
    const name = window.prompt('Nome do dispositivo (vazio para remover):', device.name || '');
    if (name === null) return;
    void act(() => request(`/api/devices/${encodeURIComponent(device.id)}`, 'PATCH', { name: name.trim() || null }));
  };
  const toggleTrust = (d:Device) => void act(()=>request(`/api/devices/${encodeURIComponent(d.id)}/trust`,'PATCH',{trusted:!d.trusted}));
  const scanPorts = async (device: Device) => {
    setScanningDevice(device.id);
    try { await act(() => request(`/api/devices/${encodeURIComponent(device.id)}/ports`, 'POST')); }
    finally { setScanningDevice(null); }
  };
  if(checkingLogin)return <div className="login-screen"><div className="login-card">Verificando sessão...</div></div>;
  if(!authorized)return <div className="login-screen"><form className="login-card" onSubmit={login}><Network size={36} color="#346fe5"/><h1>Network Monitor</h1><p>Acesso local protegido</p><label htmlFor="password">Senha do administrador</label><input id="password" type="password" autoComplete="current-password" value={password} onChange={e=>setPassword(e.target.value)} required minLength={12}/>{loginError&&<div className="alert">{loginError}</div>}<button className="primary" type="submit">Entrar</button></form></div>;
  const editMetadata=(d:Device)=>{setEditor(d.id);setNotes(d.notes||'');setTags((d.tags||[]).join(', '));};
  const saveMetadata=async()=>{
    if(!editor)return;
    await act(()=>request(`/api/devices/${encodeURIComponent(editor)}/metadata`,'PATCH',{notes,tags:tags.split(',').map(t=>t.trim()).filter(Boolean)}));
    setEditor(null);
  };
  return <div className="app">
    <aside className="sidebar">
      <div className="brand"><div className="brandicon"><Network size={22}/></div><div><strong>Network Monitor</strong><small>Monitoramento v0.5</small></div></div>
      <button className={`nav ${tab==='overview'?'active':''}`} onClick={()=>setTab('overview')}><Activity size={19}/> Visão geral</button>
      <button className={`nav ${tab==='map'?'active':''}`} onClick={()=>setTab('map')}><Cable size={19}/> Mapa da rede</button>
      <button className={`nav ${tab==='settings'?'active':''}`} onClick={()=>setTab('settings')}><ShieldCheck size={19}/> Configurações</button>
      <div className="sidebar-bottom"><ShieldCheck size={18}/><div>Modo local<small>API restrita ao computador</small></div></div>
    </aside>
    <main>
      <header><div><div className="eyebrow">PAINEL DE CONTROLE</div><h1>Visão geral da rede</h1><p>Descoberta, disponibilidade, tráfego do Windows e alertas Telegram.</p></div><div className={`connection ${connected?'good':''}`}><span className="dot"/>{connected?'Conectado à API':'API desconectada'}</div></header>
      {tab==='settings'&&<section className="panel settings-panel"><div className="panel-head"><h2>Configurações de monitoramento</h2></div><form onSubmit={e=>{e.preventDefault();void act(()=>request('/api/settings','PATCH',settings));}}><label>Intervalo de descoberta (30–3600 s)<input type="number" min="30" max="3600" value={settings.scanIntervalSeconds} onChange={e=>setSettings({...settings,scanIntervalSeconds:Number(e.target.value)})}/></label><label>Intervalo de latência (60–3600 s)<input type="number" min="60" max="3600" value={settings.probeIntervalSeconds} onChange={e=>setSettings({...settings,probeIntervalSeconds:Number(e.target.value)})}/></label><button className="primary" type="submit">Salvar preferências</button></form><div className="panel-head"><h2>Alterar senha do administrador</h2></div><form onSubmit={e=>{e.preventDefault();void act(async()=>{await request('/api/password','POST',{oldPassword,newPassword});setOldPassword('');setNewPassword('');setAuthorized(false);});}}><label>Senha atual<input type="password" autoComplete="current-password" value={oldPassword} onChange={e=>setOldPassword(e.target.value)} required/></label><label>Nova senha (mínimo 12 caracteres)<input type="password" minLength={12} maxLength={256} autoComplete="new-password" value={newPassword} onChange={e=>setNewPassword(e.target.value)} required/></label><button className="primary" type="submit">Alterar senha e encerrar sessões</button></form><div className="panel-head"><button className="scan-device" onClick={()=>void logout()}>Sair da sessão</button></div></section>}
      {tab==='map'&&<section className="panel"><div className="panel-head"><div><h2>Mapa lógico da rede</h2><p>Dispositivos descobertos pela interface selecionada</p></div></div><NetworkMap devices={data.devices} gateway={data.diagnostics?.gateway.ip??null} onSelect={id=>{setEditor(id);const d=data.devices.find(x=>x.id===id);if(d){setNotes(d.notes||'');setTags((d.tags||[]).join(', '));}}}/></section>}
      {editor&&<section className="panel settings-panel"><div className="panel-head"><h2>Notas e etiquetas · {data.devices.find(d=>d.id===editor)?.ip}</h2><button onClick={()=>setEditor(null)} className="scan-device">Fechar</button></div><form onSubmit={e=>{e.preventDefault();void saveMetadata();}}><label>Etiquetas separadas por vírgulas (até 12)<input value={tags} onChange={e=>setTags(e.target.value)} maxLength={395}/></label><label>Anotações (até 600 caracteres)<textarea value={notes} onChange={e=>setNotes(e.target.value)} maxLength={600} rows={3}/></label><button type="submit" className="primary">Salvar inventário</button></form></section>}
      <section className="toolbar"><div className="field"><label htmlFor="network">Interface monitorada</label><select id="network" value={selected?.id || ''} disabled={data.scanning} onChange={e => void act(() => request('/api/network','POST',{id:e.target.value}))}>
        {data.interfaces.length===0 && <option value="">Nenhuma interface encontrada</option>}
        {data.interfaces.map(n => <option key={n.id} value={n.id}>{n.name} · {n.cidr}{!n.supported?' (não suportada)':''}</option>)}
      </select></div><button className="primary" disabled={data.scanning || !selected?.supported} onClick={() => void act(() => request('/api/scan','POST'))}><RefreshCw size={17} className={data.scanning?'spin':''}/>{data.scanning?'Verificando...':'Verificar agora'}</button></section>
      <div className="mode-info">Descoberta: <strong>{data.mode === 'nmap' ? 'Nmap ativo' : 'Ping + ARP (fallback)'}</strong> · Portas TCP: {data.nmapInstalled ? 'disponíveis sob demanda' : 'instale o Nmap no Windows'}</div>
      {(data.error || actionError) && <div className="alert"><CircleHelp size={18}/>{actionError || data.error}</div>}
      <section className="stats">
        <div className="stat"><div className="stat-top">Total detectado <Network size={20}/></div><div className="stat-number">{data.stats.total}</div><span>Identificados nesta rede</span></div>
        <div className="stat"><div className="stat-top">Confirmados online <Wifi size={20}/></div><div className="stat-number green">{data.stats.online}</div><span>Responderam ao ping</span></div>
        <div className="stat"><div className="stat-top">Observados via ARP <RadioTower size={20}/></div><div className="stat-number amber">{data.stats.observed}</div><span>Presença não confirmada</span></div>
        <div className="stat"><div className="stat-top">Offline <Clock3 size={20}/></div><div className="stat-number">{data.stats.offline}</div><span>Não detectados agora</span></div>
      </section>
      <section className="panel diagnostics"><div className="panel-head"><div><h2>Diagnóstico de conectividade</h2><p>Gateway local, resolução DNS e acesso externo.</p></div><div className="actions"><button className="scan-device" disabled={data.diagnosticsBusy} onClick={()=>void act(()=>request('/api/diagnostics','POST'))}>{data.diagnosticsBusy?'Diagnosticando...':'Executar diagnóstico'}</button><button className="scan-device" disabled={data.probing||data.scanning} onClick={()=>void act(()=>request('/api/probe','POST'))}>{data.probing?'Medindo...':'Medir latência'}</button><a className="scan-device" href="/api/inventory.csv" download>Exportar CSV</a></div></div>
      {data.diagnostics ? <div className="diagnostics-grid"><div><strong>Gateway</strong><span>{data.diagnostics.gateway.ip||'Não identificado'} · {data.diagnostics.gateway.probe ? (data.diagnostics.gateway.probe.reachable ? `${data.diagnostics.gateway.probe.latencyMs??'?'} ms`:'Sem resposta ICMP'):'Não testado'}</span></div><div><strong>DNS</strong><span>{data.diagnostics.dns.ok?`OK · ${data.diagnostics.dns.address}`:'Falha na resolução'}</span></div><div><strong>Internet</strong><span>{data.diagnostics.internet.ok?`HTTP ${data.diagnostics.internet.status} · Acessível`:'Sem confirmação de acesso'}</span></div></div> : <div className="empty">Execute o diagnóstico para verificar os principais pontos da conectividade.</div>}
      </section>
      <section className="panel"><div className="panel-head"><div><h2>Tráfego dos adaptadores Windows</h2><p>Contadores locais Get-NetAdapterStatistics · não representa tráfego individual dos clientes Wi-Fi.</p></div><select aria-label="Adaptador de tráfego" className="adapter-select" value={activeAdapter} onChange={e=>setAdapter(e.target.value)}>{adapters.length===0?<option value="">Sem leituras</option>:adapters.map(a=><option key={a} value={a}>{a}</option>)}</select></div>
        {data.trafficError && <div className="alert">Falha na leitura de tráfego: {data.trafficError}</div>}
        <TrafficChart samples={data.traffic} adapter={activeAdapter}/>
      </section>
      <section className="panel"><div className="panel-head"><div><h2>Relatório de disponibilidade</h2><p>Percentuais calculados somente sobre amostras ICMP registradas, não sobre tempo contínuo.</p></div><a className="scan-device" href="/api/availability.csv" download>Exportar disponibilidade CSV</a></div>
        <div className="table-wrap"><table><thead><tr><th>Dispositivo</th><th>Amostras</th><th>Respostas</th><th>Disponibilidade</th><th>Latência média</th></tr></thead><tbody>{data.availability.map(r=><tr key={r.deviceId}><td>{r.name || r.ip}</td><td>{r.samples}</td><td>{r.responsive}</td><td>{r.samples?`${r.uptimePct.toFixed(2)}%`:'Sem dados'}</td><td>{r.averageLatencyMs===null?'—':`${r.averageLatencyMs.toFixed(1)} ms`}</td></tr>)}</tbody></table>{data.availability.length===0&&<div className="empty">Nenhuma medição disponível.</div>}</div>
      </section>
      <section className="panel"><div className="panel-head"><div><h2>Alertas pelo Telegram</h2><p>Notificações para novos dispositivos não reconhecidos e dispositivos confiáveis indisponíveis.</p></div><span className={`connection ${data.telegramConfigured?'good':''}`}><span className="dot"/>{data.telegramConfigured?'Configurado via .env':'Não configurado'}</span></div><p className="integration-note">Configure TELEGRAM_BOT_TOKEN e TELEGRAM_CHAT_ID no arquivo .env da raiz. O bot envia alertas após a descoberta, quando há mudança relevante. Credenciais nunca são expostas no painel.</p></section>
      <section className="panel"><div className="panel-head"><div><h2>Dispositivos da rede</h2><p>{selected ? `${selected.name} · ${selected.cidr}`:'Selecione uma rede para iniciar'}</p></div><span className="scan-time"><Clock3 size={15}/> Última varredura: {dateTime(data.lastScan)}</span></div>
        <div className="filters"><div className="search"><Search size={18}/><input placeholder="Buscar nome, hostname, fabricante, IP, MAC ou porta" value={query} onChange={e=>setQuery(e.target.value)}/></div><div className="tabs">{([['all','Todos'],['online','Online'],['observed','ARP'],['offline','Offline']] as const).map(([key,label])=><button key={key} className={filter===key?'active':''} onClick={()=>setFilter(key)}>{label}</button>)}</div><label className="unknown-toggle"><input type="checkbox" checked={alertsOnly} onChange={e=>setAlertsOnly(e.target.checked)}/> Não confiáveis ativos ({unknownCount})</label></div>
        <div className="table-wrap"><table><thead><tr><th>Dispositivo</th><th>IP local</th><th>MAC</th><th>Fabricante</th><th>Tipo provável</th><th>Portas TCP</th><th>Etiquetas</th><th>Confiança</th><th>Status</th><th>Visto por último</th><th>Ações</th></tr></thead><tbody>{visible.map(d=><tr key={d.id}>
          <td><div className="device"><div className="device-icon">{typeIcon(d.kind)}</div><div><strong>{d.name || d.hostname || 'Dispositivo não identificado'}</strong><small>{d.name ? d.hostname || 'Nome personalizado' : d.hostname ? 'Hostname detectado' : 'Sem hostname identificado'}</small></div></div></td>
          <td className="mono">{d.ip}</td><td className="mono">{d.mac||'—'}</td><td>{d.vendor||'Não identificado'}</td><td>{kindLabel[d.kind]||'Desconhecido'}</td>
          <td>{d.ports_scanned_at ? <span title={`Consultado em ${dateTime(d.ports_scanned_at)}`}>{d.ports.length ? d.ports.map(p=>`${p.port}/${p.service}`).join(', ') : 'Nenhuma das portas testadas aberta'}</span> : 'Não consultadas'}</td>
          <td>{(d.tags||[]).join(', ')||'—'}</td><td><button className={`trust ${d.trusted?'trusted':'untrusted'}`} title="Marcar dispositivo como confiável ou não confiável" onClick={()=>toggleTrust(d)}>{d.trusted?'Confiável':'Não reconhecido'}</button></td>
          <td><span className={`status ${d.status}`}><span className="dot"/>{d.status==='online'?'Online':d.status==='observed'?'ARP':'Offline'}</span></td><td className="muted">{dateTime(d.last_seen)}</td>
          <td><div className="actions"><button className="icon-button" title="Renomear dispositivo" aria-label={`Renomear ${d.ip}`} onClick={()=>rename(d)}><Pencil size={16}/></button><button className="scan-device" title="Verificar portas TCP comuns neste dispositivo" disabled={data.scanning || data.portBusy || !data.nmapInstalled || scanningDevice!==null} onClick={()=>void scanPorts(d)}>{scanningDevice===d.id?'Analisando...':'Portas TCP'}</button><button className="scan-device" onClick={()=>setChartDevice(chartDevice===d.id?null:d.id)}>Latência</button><button className="scan-device" onClick={()=>editMetadata(d)}>Notas</button></div></td>
        </tr>)}</tbody></table>{visible.length===0 && <div className="empty">Nenhum dispositivo corresponde ao filtro selecionado.</div>}</div>
      </section>
      {chartDevice && <section className="panel"><div className="panel-head"><div><h2>Histórico de latência</h2><p>{data.devices.find(d=>d.id===chartDevice)?.ip||''} · últimas medições ICMP</p></div><button className="scan-device" onClick={()=>setChartDevice(null)}>Fechar</button></div><LatencyChart samples={samples}/></section>}
      <section className="panel history"><div className="panel-head"><div><h2>Eventos recentes</h2><p>Histórico de descoberta e alterações de estado.</p></div><ArrowDownUp size={19}/></div><div className="events">{data.events.length===0?<div className="empty">Ainda não existem eventos registrados.</div>:data.events.slice(0,12).map(e=><div className="event" key={e.id}><span className="event-mark"/><strong>{e.ip}</strong><span>{e.kind==='new'?'Novo dispositivo':e.kind==='online'?'Confirmado online':e.kind==='observed'?'Observado via ARP':'Indisponível'}</span><time>{dateTime(e.created_at)}</time></div>)}</div></section>
      <footer>Descoberta a cada 60 segundos · Latência a cada 5 minutos · Tráfego local a cada 15 segundos · API em localhost · sessão autenticada.</footer>
    </main>
  </div>;
}

createRoot(document.getElementById('root')!).render(<React.StrictMode><App/></React.StrictMode>);
