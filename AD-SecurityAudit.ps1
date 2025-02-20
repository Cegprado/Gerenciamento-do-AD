# Função para registrar mensagens em um arquivo de log e exibir no console
function Log-Mensagem {
    param (
        [string]$mensagem,
        [string]$cor = "White"  # Cor padrão para mensagens no console
    )
    $logPath = "C:\Logs\SegurancaAD.log"
    $logDir = Split-Path -Path $logPath -Parent

    # Cria o diretório se ele não existir
    if (-not (Test-Path -Path $logDir)) {
        New-Item -ItemType Directory -Path $logDir | Out-Null
    }

    # Gera o timestamp
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

    # Exibe a mensagem no console com a cor especificada
    Write-Host "[$timestamp] $mensagem" -ForegroundColor $cor

    # Registra a mensagem no arquivo de log
    Add-Content -Path $logPath -Value "[$timestamp] $mensagem"
}

# Função para validar a escolha do usuário
function Get-ValidChoice {
    param ([int]$min, [int]$max)
    do {
        $choice = Read-Host "Escolha uma opção ($min-$max)"
    } while ($choice -notmatch "^\d+$" -or $choice -lt $min -or $choice -gt $max)
    return $choice
}

# Menu de Segurança e Auditoria no Active Directory
function Show-Menu {
    Clear-Host
    Write-Host "===============================================" -ForegroundColor Cyan
    Write-Host "        MENU DE SEGURANÇA E AUDITORIA" -ForegroundColor Yellow
    Write-Host "===============================================" -ForegroundColor Cyan
    Write-Host "1. Listar contas com permissões administrativas" -ForegroundColor Green
    Write-Host "2. Exibir logs de alterações recentes no AD" -ForegroundColor Green
    Write-Host "3. Listar contas com senhas fracas" -ForegroundColor Green
    Write-Host "4. Listar usuários com senha nunca expira" -ForegroundColor Green
    Write-Host "5. Listar contas que não alteram a senha há mais de 60 dias" -ForegroundColor Green
    Write-Host "6. Exibir tentativas de login com falha" -ForegroundColor Green
    Write-Host "7. Verificar membros do grupo Domain Admins" -ForegroundColor Green
    Write-Host "8. Listar usuários com permissão de delegação" -ForegroundColor Green
    Write-Host "9. Sair" -ForegroundColor Red
    Write-Host "===============================================" -ForegroundColor Cyan
}

function Get-AdminAccounts {
    try {
        Log-Mensagem "Listando contas com permissões administrativas..." -cor "Yellow"

        $AdminGroup = Get-ADGroup -Filter { Name -eq "Domain Admins" } -ErrorAction Stop
        $AdminUsers = Get-ADGroupMember -Identity $AdminGroup.DistinguishedName -ErrorAction Stop

        if ($AdminUsers.Count -gt 0) {
            Log-Mensagem "Contas encontradas! Exibindo lista..." -cor "Green"
            $AdminUsers | ForEach-Object {
                Log-Mensagem "Usuário: $($_.SamAccountName), Nome Completo: $($_.Name)" -cor "White"
            }
        } else {
            Log-Mensagem "Nenhuma conta administrativa encontrada." -cor "Cyan"
        }
    } catch {
        Log-Mensagem "Erro ao listar contas administrativas: $_" -cor "Red"
    } finally {
        Log-Mensagem "Consulta finalizada." -cor "Cyan"
        Read-Host "\nPressione Enter para continuar..."
    }
}

function Get-ADChangeLogs {
    param (
        [string]$Object = "CN=Users,DC=carlos,DC=local",
        [string]$Server = "WIN-UBKPCHH8GA0"
    )

    try {
        Write-Host "Exibindo logs de alterações recentes no AD..." -ForegroundColor Yellow

        # Validação básica dos parâmetros
        if (-not $Object -or -not $Server) {
            throw "Objeto e servidor devem ser fornecidos."
        }

        # Recupera e exibe os logs de alterações
        $logs = Get-ADReplicationAttributeMetadata -Object $Object -Server $Server -ErrorAction Stop
        $logs | Format-Table AttributeName, Version, LastOriginatingChangeTime, LastOriginatingDC -AutoSize

    } catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
        Write-Host "Erro: Objeto não encontrado no AD." -ForegroundColor Red
    } catch [Microsoft.ActiveDirectory.Management.ADServerDownException] {
        Write-Host "Erro: Servidor do AD não está disponível." -ForegroundColor Red
    } catch {
        Write-Host "Erro ao exibir logs de alterações: $_" -ForegroundColor Red
    } finally {
        Read-Host "`nPressione Enter para continuar..."
    }
}

function Get-WeakPasswords {
    try {
        Log-Mensagem "Listando contas com senhas fracas." -cor "Yellow"
        Write-Host "Contas com senhas fracas:" -ForegroundColor Yellow

        $OU = Read-Host "Digite a OU para filtrar (deixe em branco para buscar em todo o domínio)"
        if ([string]::IsNullOrWhiteSpace($OU)) { $OU = $null }

        $filtro = { Enabled -eq $true }
        $usuarios = if ($OU) {
            Get-ADUser -Filter $filtro -SearchBase $OU -Properties Name, SamAccountName, PasswordLastSet, PasswordNeverExpires
        } else {
            Get-ADUser -Filter $filtro -Properties Name, SamAccountName, PasswordLastSet, PasswordNeverExpires
        }

        $usuarios | ForEach-Object {
            $user = $_
            if ($user.PasswordLastSet -eq $null -or $user.PasswordNeverExpires -eq $true) {
                [PSCustomObject]@{
                    Name = $user.Name
                    SamAccountName = $user.SamAccountName
                    PasswordLastSet = $user.PasswordLastSet
                    PasswordNeverExpires = $user.PasswordNeverExpires
                }
            }
        } | Format-Table -AutoSize
    } catch {
        Log-Mensagem "Erro ao listar contas com senhas fracas: $_" -cor "Red"
    } finally {
        Read-Host "\nPressione Enter para continuar..."
    }
}

function Get-NeverExpirePasswords {
    try {
        Log-Mensagem "Listando usuários com senha nunca expira." -cor "Yellow"
        Write-Host "Usuários com senha nunca expira:" -ForegroundColor Yellow

        $OU = Read-Host "Digite a OU para filtrar (deixe em branco para buscar em todo o domínio)"
        if ([string]::IsNullOrWhiteSpace($OU)) { $OU = $null }

        $filtro = { Enabled -eq $true -and PasswordNeverExpires -eq $true }
        $usuarios = if ($OU) {
            Get-ADUser -Filter $filtro -SearchBase $OU -Properties Name, SamAccountName, PasswordNeverExpires
        } else {
            Get-ADUser -Filter $filtro -Properties Name, SamAccountName, PasswordNeverExpires
        }

        if ($usuarios.Count -gt 0) {
            $usuarios | Select-Object Name, SamAccountName, PasswordNeverExpires | Format-Table -AutoSize
        } else {
            Write-Host "Nenhum usuário encontrado com senha que nunca expira." -ForegroundColor Cyan
        }
    } catch {
        Log-Mensagem "Erro ao listar usuários com senha nunca expira: $_" -cor "Red"
    } finally {
        Read-Host "\nPressione Enter para continuar..."
    }
}

function Get-OldPasswords {
    try {
        Log-Mensagem "Listando contas que não alteram a senha há mais de 60 dias." -cor "Yellow"
        Write-Host "Contas que não alteram a senha há mais de 60 dias:" -ForegroundColor Yellow

        $date = (Get-Date).AddDays(-60)
        Get-ADUser -Filter { Enabled -eq $true } -Properties PasswordLastSet |
            Where-Object { $_.PasswordLastSet -lt $date } |
            Select-Object Name, SamAccountName, PasswordLastSet | Format-Table -AutoSize
    } catch {
        Log-Mensagem "Erro ao listar contas com senhas antigas: $_" -cor "Red"
    } finally {
        Read-Host "\nPressione Enter para continuar..."
    }
}
function Get-FailedLogins {
    try {
        Log-Mensagem "Exibindo tentativas de login com falha." -cor "Yellow"
        Write-Host "Tentativas de login com falha:" -ForegroundColor Yellow

        # Busca eventos de falha de logon (ID 4625)
        $events = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625} -MaxEvents 10 -ErrorAction Stop

        # Processa cada evento para extrair informações
        $events | ForEach-Object {
            $event = $_
            $message = $event.Message

            # Extrai o nome do usuário da mensagem
            if ($message -match "Account Name:\s+(\S+)") {
                $userName = $matches[1]
            } else {
                $userName = "Desconhecido"
            }

            # Extrai o nome do computador (se necessário)
            if ($message -match "Workstation Name:\s+(\S+)") {
                $workstationName = $matches[1]
            } else {
                $workstationName = "Desconhecido"
            }

            # Exibe os detalhes do evento
            [PSCustomObject]@{
                TimeCreated      = $event.TimeCreated
                UserName         = $userName
                WorkstationName = $workstationName
                Message         = $message
            }
        } | Format-Table TimeCreated, UserName, WorkstationName, Message -AutoSize

    } catch {
        Log-Mensagem "Erro ao exibir tentativas de login com falha: $_" -cor "Red"
    } finally {
        Read-Host "\nPressione Enter para continuar..."
    }
}

function Get-DomainAdmins {
    try {
        Log-Mensagem "Verificando membros do grupo Domain Admins." -cor "Yellow"
        Write-Host "Membros do grupo Domain Admins:" -ForegroundColor Yellow

        Get-ADGroupMember -Identity "Domain Admins" |
            Where-Object { (Get-ADUser -Identity $_ -Properties Enabled).Enabled -eq $true } |
            Select-Object Name, SamAccountName | Format-Table -AutoSize
    } catch {
        Log-Mensagem "Erro ao verificar membros do grupo Domain Admins: $_" -cor "Red"
    } finally {
        Read-Host "\nPressione Enter para continuar..."
    }
}

function Get-DelegationUsers {
    try {
        Log-Mensagem "Listando usuários com permissão de delegação." -cor "Yellow"
        Write-Host "Usuários com permissão de delegação:" -ForegroundColor Yellow

        $usuarios = Get-ADUser -Filter { Enabled -eq $true } -Properties TrustedForDelegation, TrustedToAuthForDelegation |
            Where-Object { $_.TrustedForDelegation -eq $true -or $_.TrustedToAuthForDelegation -eq $true } |
            Select-Object Name, SamAccountName, TrustedForDelegation, TrustedToAuthForDelegation

        if ($usuarios) {
            $usuarios | Format-Table -AutoSize
        } else {
            Write-Host "Nenhum usuário encontrado com permissão de delegação." -ForegroundColor Cyan
        }
    } catch {
        Log-Mensagem "Erro ao listar usuários com permissão de delegação: $_" -cor "Red"
    } finally {
        Read-Host "\nPressione Enter para continuar..."
    }
}

# Loop principal do menu
while ($true) {
    try {
        Show-Menu
        $choice = Get-ValidChoice -min 1 -max 9
        switch ($choice) {
            "1" { Get-AdminAccounts }
            "2" { Get-ADChangeLogs }
            "3" { Get-WeakPasswords }
            "4" { Get-NeverExpirePasswords }
            "5" { Get-OldPasswords }
            "6" { Get-FailedLogins }
            "7" { Get-DomainAdmins }
            "8" { Get-DelegationUsers }
            "9" { exit }
            default { Write-Host "Opção inválida, tente novamente." -ForegroundColor Red }
        }
    } catch {
        Log-Mensagem "Erro inesperado no menu principal: $_" -cor "Red"
    }
}