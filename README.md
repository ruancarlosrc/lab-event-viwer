# 🛡️ Windows Fundamentals — Detecção de Persistência

**Lab de Blue Team | Fundamentos Windows para SOC**  
Simulação de técnicas de persistência no Windows e detecção utilizando ferramentas nativas: Task Scheduler, Registry, Event Viewer e PowerShell.

---

## 🎯 Objetivo

Simular dois mecanismos clássicos de persistência utilizados por atacantes e detectá-los através de análise de logs, auditoria do sistema e automação com PowerShell — replicando o fluxo de trabalho de um analista SOC durante triagem de incidente.

---

## 🗺️ Mapeamento MITRE ATT&CK

| Técnica | ID | Descrição |
|---|---|---|
| Scheduled Task/Job | T1053.005 | Persistência via tarefa agendada |
| Registry Run Keys | T1547.001 | Persistência via chave Run do registro |
| PowerShell | T1059.001 | Execução via PowerShell |
| Impair Defenses | T1562.002 | Habilitação de auditoria como medida defensiva |

---

## 🧰 Ferramentas Utilizadas

- Windows 10 (VM VirtualBox)
- Task Scheduler (`taskschd.msc`)
- Registry Editor (`regedit.exe`)
- Event Viewer (`eventvwr.msc`)
- PowerShell (Admin)
- `auditpol.exe`, `schtasks.exe`, `reg.exe`

---

## 📋 Ambiente

| Item | Detalhe |
|---|---|
| Sistema | Windows 10 (VM) |
| Usuário | `user` @ `DESKTOP-GPM14TF` |
| Idioma | PT-BR |
| Hypervisor | Oracle VirtualBox |

---

## 🔴 Fase 1 — Task Scheduler (T1053.005)

### Objetivo
Simular criação de tarefas agendadas maliciosas com nomes que imitam processos legítimos do Windows.

### Configuração de auditoria
```powershell
# GUID universal — funciona em qualquer idioma do Windows
auditpol /set /subcategory:"{0CCE9232-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable
```

> ⚠️ **Lição aprendida:** O comando com nome em inglês (`"Other Object Access Events"`) falha em sistemas PT-BR. O uso do GUID é a abordagem correta e portável.

### Tarefas criadas

**Tarefa 1 — via GUI (WindowsUpdateHelper)**
```xml
<Command>cmd.exe</Command>
<Arguments>/c "echo pwned > C:\Users\Public\persist.txt"</Arguments>
<RunLevel>HighestAvailable</RunLevel>
<Triggers>
  <LogonTrigger/>
  <BootTrigger/>
</Triggers>
```

**Tarefa 2 — via linha de comando (SecurityHealthUpdate)**
```powershell
schtasks /create /tn "SecurityHealthUpdate" /tr "powershell.exe -WindowStyle Hidden -Command 'whoami > C:\Users\Public\recon.txt'" /sc onlogon /ru SYSTEM /f
```
```xml
<Command>powershell.exe</Command>
<Arguments>-WindowStyle Hidden -Command "whoami > C:\Users\Public\recon.txt"</Arguments>
<UserId>S-1-5-18</UserId>  <!-- SYSTEM -->
```

> 🚩 **Red flags no XML:** `RunLevel: HighestAvailable`, `Hidden: true`, execução como `SYSTEM (S-1-5-18)`, trigger em logon e boot simultaneamente.

### Listagem de tarefas fora do namespace Microsoft
```powershell
Get-ScheduledTask | Where-Object { $_.TaskPath -notlike "\Microsoft\*" } |
    Select-Object TaskName, TaskPath, State | Format-Table -AutoSize
```

---

## 🔴 Fase 2 — Registry Run Keys (T1547.001)

### Objetivo
Simular persistência via Run Key usando o mesmo nome da tarefa da Fase 1 — técnica comum para dificultar correlação.

### Baseline antes da modificação
```
[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run]
# Chave vazia — nenhuma entrada de autorun para o usuário
```

### Run Key criada
```powershell
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "WindowsUpdateHelper" /t REG_SZ /d "powershell.exe -WindowStyle Hidden -Command 'whoami > C:\Users\Public\recon2.txt'" /f
```

### Estado após modificação
```
[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run]
"WindowsUpdateHelper"="powershell.exe -WindowStyle Hidden -Command 'whoami > C:\Users\Public\recon2.txt'"
```

### Varredura das quatro Run Keys principais
```powershell
$keys = @(
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
)
foreach ($key in $keys) {
    Write-Host "`n=== $key ===" -ForegroundColor Cyan
    Get-ItemProperty $key -ErrorAction SilentlyContinue
}
```

**Resultado:** `WindowsUpdateHelper` encontrada em `HKCU\Run` com payload de PowerShell oculto. Entradas legítimas identificadas: `SecurityHealth`, `VBoxTray`, `MicrosoftEdgeAutoLaunch`.

> 🚩 **Red flags:** PowerShell com `-WindowStyle Hidden`, nome imitando processo do Windows, mesmo nome usado em múltiplos mecanismos de persistência simultaneamente.

---

## 🔵 Fase 3 — Event Viewer (Análise de Logs)

### Auditoria habilitada

```powershell
# Criação de processos (Event ID 4688)
auditpol /set /subcategory:"{0CCE922B-69AE-11D9-BED3-505054503030}" /success:enable

# Command line logging (requer gpupdate /force + reboot para aplicar)
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f
gpupdate /force
```

### Event IDs relevantes

| Event ID | Log | Significado |
|---|---|---|
| 4698 | Security | Tarefa agendada criada |
| 4702 | Security | Tarefa agendada modificada |
| 4657 | Security | Valor do registro modificado |
| **4688** | Security | **Novo processo criado** ✅ capturado |
| 4624 | Security | Logon bem-sucedido |
| 4625 | Security | Falha de logon |
| **4104** | PS/Operational | **Script Block Logging** ✅ capturado |

### Evidências capturadas — Event ID 4688

**schtasks.exe invocado pelo powershell.exe (Fase 1):**
```
Nome do Novo Processo:   C:\Windows\System32\schtasks.exe
Nome do Processo do Criador: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
Linha de Comando: "C:\Windows\system32\schtasks.exe" /create /tn TestCmdLine /tr "powershell.exe -Command 'whoami'" /sc onlogon /f
```

**reg.exe invocado pelo powershell.exe (Fase 2):**
```
Nome do Novo Processo:   C:\Windows\System32\reg.exe
Nome do Processo do Criador: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
```

**whoami.exe executado como SYSTEM — payload rodando:**
```
Nome do Novo Processo:   C:\Windows\System32\whoami.exe
Nome do Processo do Criador: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
ID de Segurança (criador): S-1-5-18 (SYSTEM)
Tipo de Elevação: %%1936 (token completo — Tipo 1)
```

> ⚠️ **Observação:** Event ID 4698 não foi gerado porque a auditoria foi habilitada após a criação das tarefas. Em ambiente real, auditoria deve estar ativa antes dos eventos. Isso demonstra a importância de auditing-first na configuração de endpoints.

> ⚠️ **Observação:** Command line logging exige `gpupdate /force` + reboot. Eventos anteriores ao reboot aparecem com campo `Linha de Comando` vazio — o contraste é visível no próprio log.

### Query PowerShell para caça de eventos
```powershell
Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=4688]]" |
    Where-Object { $_.Message -like "*schtasks*" -or $_.Message -like "*reg.exe*" -or $_.Message -like "*whoami*" } |
    Select-Object TimeCreated, Message |
    Export-Csv C:\Users\Public\evidence_4688.csv -NoTypeInformation -Encoding UTF8
```

---

## 🟢 Fase 4 — PowerShell (Automação de Detecção)

### Script Block Logging habilitado
```powershell
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f
gpupdate /force
```

Event ID **4104** registrado após execução do script:
```
ID de ScriptBlock: 526593ae-5b4a-449c-bb69-f3c2ee8b05aa
Caminho: C:\Users\Public\detect_persistence.ps1
```

### Script de detecção — detect_persistence.ps1

Script desenvolvido para varrer automaticamente três vetores de persistência e exportar relatório CSV:

- **Bloco 1:** Tarefas agendadas fora de `\Microsoft\` → MITRE T1053.005
- **Bloco 2:** Run Keys nas quatro chaves principais (HKCU + HKLM) → MITRE T1547.001
- **Bloco 3:** Event ID 4688 das últimas 24h filtrando processos suspeitos → MITRE T1059.001

### Resultado da execução
```
[*] Iniciando varredura de persistência...
[*] Verificando tarefas agendadas suspeitas...
    Encontradas: 6 tarefa(s)
[*] Verificando Run Keys...
    Encontradas: 4 entrada(s)
[*] Verificando Event ID 4688 (últimas 24h)...
    Encontrados: 11 evento(s)
[+] Relatório exportado: persistence_report_2026-06-09_11-36.csv
[+] Total de artefatos encontrados: 21
```

**Artefatos maliciosos identificados pelo script:**

| Tipo | Nome | Indicador |
|---|---|---|
| ScheduledTask | `WindowsUpdateHelper` | Payload cmd.exe, trigger boot+logon |
| ScheduledTask | `SecurityHealthUpdate` | Execução como SYSTEM, PS oculto |
| ScheduledTask | `TestCmdLine` | PowerShell com whoami |
| RunKey | `WindowsUpdateHelper` | PS `-WindowStyle Hidden` em HKCU |
| ProcessEvent | `schtasks.exe` | Invocado por powershell.exe |
| ProcessEvent | `whoami.exe` | Executado como SYSTEM |

---

## 📊 Lições Aprendidas

| # | Lição |
|---|---|
| 1 | Usar GUIDs no `auditpol` garante compatibilidade entre idiomas |
| 2 | Command line logging exige reboot — eventos anteriores ficam sem esse campo |
| 3 | Event ID 4698 só é gerado se auditoria estiver ativa no momento da criação |
| 4 | Cadeia `powershell.exe → schtasks.exe` ou `powershell.exe → reg.exe` é indicador de alerta |
| 5 | Processos executando como SYSTEM com token Tipo 1 merecem investigação imediata |
| 6 | Nomear artefatos maliciosos igual a processos legítimos é técnica real de evasão |

---

## 🔗 Referências

- [MITRE ATT&CK T1053.005](https://attack.mitre.org/techniques/T1053/005/)
- [MITRE ATT&CK T1547.001](https://attack.mitre.org/techniques/T1547/001/)
- [Windows Security Event IDs — ultimatewindowssecurity.com](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/)
- [Auditpol GUIDs Reference](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-other-object-access-events)
