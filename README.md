# Network Monitor v0.5 — Windows

Dashboard e agente local para inventário, descoberta e diagnóstico de redes IPv4 Wi-Fi e Ethernet.

## Requisitos

- Windows 10/11, Node.js 22 ou superior, npm.
- Nmap opcional, mas recomendado para descoberta e inspeção de portas.
- Uso restrito às redes que você administra e tem autorização para monitorar.

## Primeira inicialização

1. Extraia o ZIP e abra PowerShell na pasta `network-monitor`.
2. Copie o exemplo de configuração:

```powershell
Copy-Item .env.example .env
notepad .env
```

3. Altere `NETWORK_MONITOR_PASSWORD=CHANGE_ME` para uma senha exclusiva com **12 a 256 caracteres**. Não compartilhe nem versione `.env`.
4. Instale e execute:

```powershell
npm install
npm run dev
```

5. Abra `http://127.0.0.1:5173` e entre com usuário `admin` e a senha configurada.

Na primeira execução, o backend cria o hash scrypt da senha no SQLite. Após isso, a variável não é mais necessária; a alteração da senha pode ser feita no painel. Em atualizações, **preserve `server/data/network-monitor.sqlite`**.

## Novidades v0.5

- Login obrigatório em todas as rotas da API e no WebSocket, sessões com tokens aleatórios e cookies `HttpOnly; SameSite=Strict`, limite de tentativas falhas.
- Alteração de senha com encerramento das sessões antigas.
- Preferências persistentes: intervalo de descoberta (30–3600 segundos) e de latência (60–3600 segundos).
- Seleção de adaptador persistida; etiquetas e notas por equipamento.
- Visualização lógica de equipamentos detectados ao redor da rede (não é topologia física). Clique nos nós para editar notas e etiquetas.
- Mantidos inventário, descoberta Nmap/ARP, diagnóstico, tráfego do computador e alertas Telegram da v0.4.

## Segurança e limitações

- Serviço e dashboard escutam apenas `127.0.0.1`, sem acesso direto de outras máquinas. **Não exponha as portas 3001 ou 5173 à internet**.
- A conexão local é HTTP. Para acesso remoto, use VPN e HTTPS com proxy reverso e ajuste as políticas de origem antes de alterar os endereços de bind.
- A detecção de dispositivos não garante visibilidade completa. MACs aleatórios, firewalls e isolamento entre clientes Wi-Fi podem ocultar equipamentos.
- Dispositivos `observed` são encontrados via ARP e podem não estar efetivamente conectados.
- O mapa é uma visualização lógica, sem inferência de portas físicas, cabos, APs ou switches.
- O tráfego mostrado corresponde ao computador Windows, não ao consumo individual de clientes da rede.
- Configurações de usuário são locais e esta versão suporta apenas um administrador.

## Testes

```powershell
npm run typecheck
npm run test -w server
npm run build
```

API: `http://127.0.0.1:3001`. Web: `http://127.0.0.1:5173`.
