export type AlertInput = { kind: string; ip: string; deviceId: string; trusted: number; name: string | null; networkId: string };
export function shouldNotify(event: AlertInput): boolean {
  return (event.kind === 'new' && !event.trusted) || (event.kind === 'offline' && !!event.trusted);
}
export function formatAlert(event: AlertInput): string {
  const label = event.name || event.ip;
  const reason = event.kind === 'new' ? 'Novo dispositivo não reconhecido' : 'Dispositivo confiável indisponível';
  return `Network Monitor: ${reason}\nDispositivo: ${label}\nIP: ${event.ip}\nRede: ${event.networkId}`;
}
export async function sendTelegram(message: string): Promise<void> {
  const token = process.env.TELEGRAM_BOT_TOKEN;
  const chatId = process.env.TELEGRAM_CHAT_ID;
  if (!token || !chatId) return;
  if (!/^\d+:[\w-]+$/.test(token) || !/^-?\d+$/.test(chatId)) throw new Error('Configuração do Telegram inválida.');
  const response = await fetch(`https://api.telegram.org/bot${token}/sendMessage`, {
    method: 'POST', headers: {'Content-Type':'application/json'},
    body: JSON.stringify({chat_id: chatId, text: message, disable_web_page_preview: true}),
    signal: AbortSignal.timeout(10000)
  });
  if (!response.ok) throw new Error(`Telegram HTTP ${response.status}`);
}
