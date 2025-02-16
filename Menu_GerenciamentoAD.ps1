#Requires -Module ActiveDirectory

<#
.SYNOPSIS
Script de gerenciamento de Active Directory com interface menu-driven.
.DESCRIPTION
Oferece diversas operações de gerenciamento de usuários, computadores e grupos no AD.
#>

function Menu {
    [CmdletBinding()]
    param()
    
    while($true) {
        Clear-Host
        Write-Host @"
                                    
"@ -ForegroundColor Blue

        Write-Host "=========================================" -ForegroundColor Cyan
        Write-Host "       MENU DE GERENCIAMENTO AD" -ForegroundColor Green
        Write-Host "========================================="
        Write-Host "Domínio: $dominio" -ForegroundColor Yellow
        Write-Host "OU Padrão Usuários: $OUUsuariosPadrao" -ForegroundColor Magenta
        Write-Host "OU Padrão Computadores: $OUComputadoresPadrao" -ForegroundColor Magenta
        Write-Host "-----------------------------------------"
        Write-Host "1  - Criar usuário no AD"
        Write-Host "2  - Inativar usuário no AD"
        Write-Host "3  - Reativar usuário no AD"
        Write-Host "4  - Deletar usuário"
        Write-Host "5  - Resetar a senha"
        Write-Host "6  - Desbloquear usuário"
        Write-Host "7  - Associar computador no AD"
        Write-Host "8  - Desassociar computador"
        Write-Host "9  - Deletar computador"
        Write-Host "10 - Alterar ramal"
        Write-Host "11 - Sincronizar AD"
        Write-Host "12 - Listar usuários"
        Write-Host "13 - Listar computadores"
        Write-Host "14 - Mover objeto para outra OU"
        Write-Host "15 - Adicionar usuário a um grupo"
        Write-Host "16 - Remover usuário de um grupo"
        Write-Host "17 - Verificar membros de um grupo"
        Write-Host "18 - Alterar atributos de um usuário"
        Write-Host "19 - Exportar relatório de usuários"
        Write-Host "20 - Exportar relatório de computadores"
        Write-Host "0  - Sair do script"
        Write-Host "-----------------------------------------"

        $opcao = Read-Host "Digite o número correspondente à opção desejada"
        
        # Verificação numérica
        if(-not ($opcao -match '^\d+$')) {
            Write-Host "Opção inválida! Digite um número." -ForegroundColor Red
            Start-Sleep -Seconds 2
            continue
        }

        switch($opcao) {
            "0" { Exit }
            "1" { CriarUsuario }
            "2" { InativarUsuario }
            "3" { ReativarUsuario }
            "4" { DeletarUsuario }
            "5" { ResetarSenha }
            "6" { DesbloquearUsuario }
            "7" { AssociarComputador }
            "8" { DesassociarComputador }
            "9" { DeletarComputador }
            "10" { AlterarRamal }
            "11" { SincronizarAD }
            "12" { ListarUsuarios }
            "13" { ListarComputadores }
            "14" { MoverOU }
            "15" { AdicionarGrupo }
            "16" { RemoverGrupo }
            "17" { VerificarGrupo }
            "18" { AlterarAtributos }
            "19" { ExportarRelatorioUsuarios }
            "20" { ExportarRelatorioComputadores }
            default { Write-Host "Opção inválida!" -ForegroundColor Red; Start-Sleep -Seconds 2 }
        }
    }
}

# Função para confirmar ações
function ConfirmarAcao {
    param([string]$mensagem)
    do {
        $resposta = Read-Host "$mensagem (S/N)"
        $resposta = $resposta.ToUpper() # Aceita maiúsculas ou minúsculas
    } while ($resposta -notmatch '^[SN]$')
    return $resposta -eq 'S'
}

# Função para criar usuário
# Função para criar usuário
function CriarUsuario {
    try {
        # Solicita o caminho do arquivo CSV ou TXT
        $caminhoArquivo = Read-Host "Digite o caminho completo do arquivo CSV ou TXT (ex: C:\usuarios.csv)"

        # Verifica se o arquivo existe
        if (-not (Test-Path $caminhoArquivo)) {
            throw "Arquivo não encontrado! Verifique o caminho e tente novamente."
        }

        # Lê o arquivo CSV
        $usuarios = Import-Csv -Path $caminhoArquivo

        # Define a OU padrão se nenhuma for fornecida
        $OU = Read-Host "Digite a OU destino [Enter para padrão]"
        if ([string]::IsNullOrWhiteSpace($OU)) {
            $OU = "OU=Usuarios,DC=carlos,DC=local" # OU padrão ajustada
        }

        # Loop para criar cada usuário
        foreach ($usuario in $usuarios) {
            # Divide o nome completo em partes
            $nomes = $usuario.NomeCompleto -split " "
            $primeiroNome = $nomes[0]  # Primeiro nome
            $ultimoNome = $nomes[-1]   # Último nome

            # Obtém a primeira letra do segundo nome, se existir
            $segundoNome = ""
            if ($nomes.Count -gt 2) {
                $segundoNome = $nomes[1]
            }

            # Cria o SamAccountName (primeira letra do primeiro nome + primeira letra do segundo nome + último nome)
            $SamAccountName = "$($primeiroNome.Substring(0,1))"
            if ($segundoNome.Length -gt 0) {
                $SamAccountName += "$($segundoNome.Substring(0,1))"
            }
            $SamAccountName += "$ultimoNome"
            $SamAccountName = $SamAccountName.ToLower()

            # Cria o UserPrincipalName (UPN) com o seu domínio
            $dominio = "carlos.local"
            $upn = "$SamAccountName@$dominio"

            # Define o nome completo
            $nomeCompleto = $usuario.NomeCompleto

            # Converte a senha para SecureString
            $senha = ConvertTo-SecureString $usuario.Senha -AsPlainText -Force

            # Verifica se o usuário já existe
            if (Get-ADUser -Filter "SamAccountName -eq '$SamAccountName'" -ErrorAction SilentlyContinue) {
                Write-Host "Usuário '$SamAccountName' já existe! Ignorando..." -ForegroundColor Red
                continue
            }

            # Cria o usuário
            $confirmacao = Read-Host "Confirma criação do usuário $SamAccountName? (S/N)"
            if ($confirmacao -match "^[Ss]$") {
                New-ADUser -Name $nomeCompleto -GivenName $primeiroNome -Surname $ultimoNome `
                    -SamAccountName $SamAccountName -UserPrincipalName $upn `
                    -AccountPassword $senha -Enabled $true -Path $OU `
                    -ChangePasswordAtLogon $true
                Write-Host "Usuário $SamAccountName criado com sucesso!" -ForegroundColor Green
            }
        }
    }
    catch [System.UnauthorizedAccessException] {
        Write-Host "Erro: Acesso negado ao arquivo. Verifique as permissões ou execute o PowerShell como administrador." -ForegroundColor Red
    }
    catch {
        Write-Host "Erro: $_" -ForegroundColor Red
    }
    finally {
        Start-Sleep -Seconds 10
    }
}



# Função para inativar usuário
function InativarUsuario {
    try {
        $entrada = Read-Host "Digite os nomes dos usuários separados por vírgula"
        $usuarios = $entrada -split ',' | ForEach-Object { $_.Trim() }

        foreach ($usuario in $usuarios) {
            if ([string]::IsNullOrWhiteSpace($usuario)) { continue }

            # Verifica se o usuário existe no AD
            $adUser = Get-ADUser -Filter "SamAccountName -eq '$usuario'" -ErrorAction SilentlyContinue
            if (-not $adUser) {
                Write-Host "Usuário '$usuario' não encontrado!" -ForegroundColor Red
                continue
            }

            if (ConfirmarAcao "Deseja inativar o usuário '$usuario'?") {
                # Desabilita a conta do usuário
                Disable-ADAccount -Identity $usuario
                Write-Host "Usuário '$usuario' inativado com sucesso!" -ForegroundColor Green

                # Remover o usuário de todos os grupos (exceto "Domain Users")
                $grupos = Get-ADPrincipalGroupMembership -Identity $usuario -ErrorAction SilentlyContinue
                if ($grupos -and $grupos.Count -gt 0) {
                    Write-Host "Removendo o usuário '$usuario' de todos os grupos..." -ForegroundColor Yellow
                    foreach ($grupo in $grupos) {
                        if ($grupo.SamAccountName -ne "Domain Users") { # Evita remover de "Domain Users"
                            Remove-ADGroupMember -Identity $grupo -Members $usuario -Confirm:$false -ErrorAction SilentlyContinue
                            Write-Host "Usuário '$usuario' removido do grupo: $($grupo.SamAccountName)" -ForegroundColor Yellow
                        }
                    }
                    Write-Host "Usuário '$usuario' removido de todos os grupos com sucesso!" -ForegroundColor Green
                } else {
                    Write-Host "O usuário '$usuario' não faz parte de nenhum grupo além do 'Domain Users'." -ForegroundColor Yellow
                }

                # Revogar horários de logon
                $logonHours = New-Object byte[] (21)  # Array de 21 bytes todos zerados (nenhum logon permitido)
                Set-ADUser -Identity $usuario -Replace @{logonHours = $logonHours} -ErrorAction SilentlyContinue
                Write-Host "Horário de logon do usuário '$usuario' foi revogado!" -ForegroundColor Green
            }
        }
    }
    catch {
        Write-Host "Erro: $($_.Exception.Message)" -ForegroundColor Red
    }
    finally {
        Start-Sleep -Seconds 5
    }
}

# Função para reativar usuário
function ReativarUsuario {
    try {
        $usuario = Read-Host "Digite o nome do usuário"
        if(-not (Get-ADUser -Filter "SamAccountName -eq '$usuario'" -ErrorAction SilentlyContinue)) {
            throw "Usuário $usuario não encontrado!"
        }

        if(ConfirmarAcao "Deseja reativar o usuário $usuario?") {
            Enable-ADAccount -Identity $usuario
            Write-Host "Usuário $usuario reativado com sucesso!" -ForegroundColor Green
        }
    }
    catch {
        Write-Host "Erro: $_" -ForegroundColor Red
    }
    finally {
        Start-Sleep -Seconds 2
    }
}

# Função para deletar usuário
function DeletarUsuario {
    try {
        $usuario = Read-Host "Digite o nome do usuário"
        if(-not (Get-ADUser -Filter "SamAccountName -eq '$usuario'" -ErrorAction SilentlyContinue)) {
            throw "Usuário $usuario não encontrado!"
        }

        if(ConfirmarAcao "Deseja deletar o usuário $usuario?") {
            Remove-ADUser -Identity $usuario -Confirm:$false
            Write-Host "Usuário $usuario deletado com sucesso!" -ForegroundColor Green
        }
    }
    catch {
        Write-Host "Erro: $_" -ForegroundColor Red
    }
    finally {
        Start-Sleep -Seconds 2
    }
}

# Função para resetar senha
function ResetarSenha {
    try {
        $usuario = Read-Host "Digite o nome do usuário"
        $novaSenha = Read-Host "Digite a nova senha" -AsSecureString
        
        if(ConfirmarAcao "Deseja realmente resetar a senha de $usuario?") {
            Set-ADAccountPassword -Identity $usuario -NewPassword $novaSenha -Reset
            Write-Host "Senha resetada com sucesso!" -ForegroundColor Green
        }
    }
    catch {
        Write-Host "Erro: $_" -ForegroundColor Red
    }
    finally {
        Start-Sleep -Seconds 2
    }
}

# Função para desbloquear usuário
function DesbloquearUsuario {
    try {
        $usuario = Read-Host "Digite o nome do usuário"
        if(-not (Get-ADUser -Filter "SamAccountName -eq '$usuario'" -ErrorAction SilentlyContinue)) {
            throw "Usuário $usuario não encontrado!"
        }

        if(ConfirmarAcao "Deseja desbloquear o usuário $usuario?") {
            Unlock-ADAccount -Identity $usuario
            Write-Host "Usuário $usuario desbloqueado com sucesso!" -ForegroundColor Green
        }
    }
    catch {
        Write-Host "Erro: $_" -ForegroundColor Red
    }
    finally {
        Start-Sleep -Seconds 2
    }
}

# Função para associar computador
function AssociarComputador {
    try {
        $computador = Read-Host "Digite o nome do computador"
        $OU = Read-Host "Digite a OU destino [Enter para padrão]"
        
        if([string]::IsNullOrWhiteSpace($OU)) {
            $OU = $OUComputadoresPadrao
        }

        if(Get-ADComputer -Filter "Name -eq '$computador'" -ErrorAction SilentlyContinue) {
            throw "Computador $computador já existe!"
        }

        if(ConfirmarAcao "Confirma associação do computador $computador?") {
            Add-Computer -ComputerName $computador -DomainName $dominio -OUPath $OU
            Write-Host "Computador $computador associado com sucesso!" -ForegroundColor Green
        }
    }
    catch {
        Write-Host "Erro: $_" -ForegroundColor Red
    }
    finally {
        Start-Sleep -Seconds 2
    }
}

# Função para desassociar computador
function DesassociarComputador {
    try {
        $computador = Read-Host "Digite o nome do computador"
        if(-not (Get-ADComputer -Filter "Name -eq '$computador'" -ErrorAction SilentlyContinue)) {
            throw "Computador $computador não encontrado!"
        }

        if(ConfirmarAcao "Deseja desassociar o computador $computador?") {
            Remove-Computer -ComputerName $computador -DomainName $dominio -Confirm:$false
            Write-Host "Computador $computador desassociado com sucesso!" -ForegroundColor Green
        }
    }
    catch {
        Write-Host "Erro: $_" -ForegroundColor Red
    }
    finally {
        Start-Sleep -Seconds 2
    }
}

# Função para deletar computador
function DeletarComputador {
    try {
        $computador = Read-Host "Digite o nome do computador"
        if(-not (Get-ADComputer -Filter "Name -eq '$computador'" -ErrorAction SilentlyContinue)) {
            throw "Computador $computador não encontrado!"
        }

        if(ConfirmarAcao "Deseja deletar o computador $computador?") {
            Remove-ADComputer -Identity $computador -Confirm:$false
            Write-Host "Computador $computador deletado com sucesso!" -ForegroundColor Green
        }
    }
    catch {
        Write-Host "Erro: $_" -ForegroundColor Red
    }
    finally {
        Start-Sleep -Seconds 2
    }
}

# Função para alterar ramal
function AlterarRamal {
    try {
        $usuario = Read-Host "Digite o nome do usuário"
        $ramal = Read-Host "Digite o novo ramal"
        
        if(-not (Get-ADUser -Filter "SamAccountName -eq '$usuario'" -ErrorAction SilentlyContinue)) {
            throw "Usuário $usuario não encontrado!"
        }

        if(ConfirmarAcao "Deseja alterar o ramal de $usuario para $ramal?") {
            Set-ADUser -Identity $usuario -OfficePhone $ramal
            Write-Host "Ramal alterado com sucesso!" -ForegroundColor Green
        }
    }
    catch {
        Write-Host "Erro: $_" -ForegroundColor Red
    }
    finally {
        Start-Sleep -Seconds 2
    }
}

# Função para sincronizar AD
function SincronizarAD {
    try {
        if(ConfirmarAcao "Deseja sincronizar o AD?") {
            Invoke-Command -ScriptBlock { repadmin /syncall }
            Write-Host "Sincronização do AD concluída!" -ForegroundColor Green
        }
    }
    catch {
        Write-Host "Erro: $_" -ForegroundColor Red
    }
    finally {
        Start-Sleep -Seconds 2
    }
}

# Função para listar usuários
function ListarUsuarios {
    try {
        $OU = Read-Host "Digite a OU para listar [Enter para padrão]"
        if([string]::IsNullOrWhiteSpace($OU)) {
            $OU = $OUUsuariosPadrao
        }

        $usuarios = Get-ADUser -Filter * -SearchBase $OU | Select-Object Name, SamAccountName, Enabled
        $usuarios | Format-Table -AutoSize
    }
    catch {
        Write-Host "Erro: $_" -ForegroundColor Red
    }
    finally {
        Read-Host "Pressione Enter para continuar..."
    }
}

# Função para listar computadores
function ListarComputadores {
    try {
        $OU = Read-Host "Digite a OU para listar [Enter para padrão]"
        if([string]::IsNullOrWhiteSpace($OU)) {
            $OU = $OUComputadoresPadrao
        }

        $computadores = Get-ADComputer -Filter * -SearchBase $OU | Select-Object Name, OperatingSystem
        $computadores | Format-Table -AutoSize
    }
    catch {
        Write-Host "Erro: $_" -ForegroundColor Red
    }
    finally {
        Read-Host "Pressione Enter para continuar..."
    }
}

# Função para mover objeto para outra OU
function MoverOU {
    try {
        $objeto = Read-Host "Digite o nome do objeto (usuário ou computador)"
        $OU = Read-Host "Digite a OU destino"
        
        if(-not (Get-ADObject -Filter "Name -eq '$objeto'" -ErrorAction SilentlyContinue)) {
            throw "Objeto $objeto não encontrado!"
        }

        if(ConfirmarAcao "Deseja mover o objeto $objeto para $OU?") {
            Move-ADObject -Identity $objeto -TargetPath $OU
            Write-Host "Objeto $objeto movido com sucesso!" -ForegroundColor Green
        }
    }
    catch {
        Write-Host "Erro: $_" -ForegroundColor Red
    }
    finally {
        Start-Sleep -Seconds 2
    }
}

# Função para adicionar usuário a um grupo
function AdicionarGrupo {
    try {
        $usuario = Read-Host "Digite o nome do usuário"
        $grupo = Read-Host "Digite o nome do grupo"
        
        if(-not (Get-ADUser -Filter "SamAccountName -eq '$usuario'" -ErrorAction SilentlyContinue)) {
            throw "Usuário $usuario não encontrado!"
        }

        if(-not (Get-ADGroup -Filter "Name -eq '$grupo'" -ErrorAction SilentlyContinue)) {
            throw "Grupo $grupo não encontrado!"
        }

        if(ConfirmarAcao "Deseja adicionar $usuario ao grupo $grupo?") {
            Add-ADGroupMember -Identity $grupo -Members $usuario
            Write-Host "Usuário $usuario adicionado ao grupo $grupo com sucesso!" -ForegroundColor Green
        }
    }
    catch {
        Write-Host "Erro: $_" -ForegroundColor Red
    }
    finally {
        Start-Sleep -Seconds 2
    }
}

# Função para remover usuário de um grupo
function RemoverGrupo {
    try {
        $usuario = Read-Host "Digite o nome do usuário"
        $grupo = Read-Host "Digite o nome do grupo"
        
        if(-not (Get-ADUser -Filter "SamAccountName -eq '$usuario'" -ErrorAction SilentlyContinue)) {
            throw "Usuário $usuario não encontrado!"
        }

        if(-not (Get-ADGroup -Filter "Name -eq '$grupo'" -ErrorAction SilentlyContinue)) {
            throw "Grupo $grupo não encontrado!"
        }

        if(ConfirmarAcao "Deseja remover $usuario do grupo $grupo?") {
            Remove-ADGroupMember -Identity $grupo -Members $usuario -Confirm:$false
            Write-Host "Usuário $usuario removido do grupo $grupo com sucesso!" -ForegroundColor Green
        }
    }
    catch {
        Write-Host "Erro: $_" -ForegroundColor Red
    }
    finally {
        Start-Sleep -Seconds 2
    }
}

# Função para verificar membros de um grupo
function VerificarGrupo {
    try {
        $grupo = Read-Host "Digite o nome do grupo"
        if(-not (Get-ADGroup -Filter "Name -eq '$grupo'" -ErrorAction SilentlyContinue)) {
            throw "Grupo $grupo não encontrado!"
        }

        $membros = Get-ADGroupMember -Identity $grupo | Select-Object Name, SamAccountName
        $membros | Format-Table -AutoSize
    }
    catch {
        Write-Host "Erro: $_" -ForegroundColor Red
    }
    finally {
        Read-Host "Pressione Enter para continuar..."
    }
}

# Função para alterar atributos de um usuário
function AlterarAtributos {
    try {
        $usuario = Read-Host "Digite o nome do usuário"
        if(-not (Get-ADUser -Filter "SamAccountName -eq '$usuario'" -ErrorAction SilentlyContinue)) {
            throw "Usuário $usuario não encontrado!"
        }

        Write-Host "Digite os atributos que deseja alterar (ex: -OfficePhone '1234' -Title 'Gerente')"
        $atributos = Read-Host "Atributos"

        if(ConfirmarAcao "Deseja alterar os atributos de $usuario?") {
            Set-ADUser -Identity $usuario -Replace $atributos
            Write-Host "Atributos de $usuario alterados com sucesso!" -ForegroundColor Green
        }
    }
    catch {
        Write-Host "Erro: $_" -ForegroundColor Red
    }
    finally {
        Start-Sleep -Seconds 2
    }
}

# Função para exportar relatório de usuários
function ExportarRelatorioUsuarios {
    try {
        $OU = Read-Host "Digite a OU para exportar [Enter para padrão]"
        if([string]::IsNullOrWhiteSpace($OU)) {
            $OU = $OUUsuariosPadrao
        }

        $caminho = Read-Host "Digite o caminho completo para salvar o relatório (ex: C:\RelatorioUsuarios.csv)"
        if (-not $caminho.EndsWith(".csv")) {
            $caminho += ".csv"
        }

        $usuarios = Get-ADUser -Filter * -SearchBase $OU | Select-Object Name, SamAccountName, Enabled
        $usuarios | Export-Csv -Path $caminho -NoTypeInformation
        Write-Host "Relatório de usuários exportado com sucesso para $caminho!" -ForegroundColor Green
    }
    catch {
        Write-Host "Erro: $_" -ForegroundColor Red
    }
    finally {
        Start-Sleep -Seconds 2
    }
}

# Função para exportar relatório de computadores
function ExportarRelatorioComputadores {
    try {
        $OU = Read-Host "Digite a OU para exportar [Enter para padrão]"
        if([string]::IsNullOrWhiteSpace($OU)) {
            $OU = $OUComputadoresPadrao
        }

        $caminho = Read-Host "Digite o caminho completo para salvar o relatório (ex: C:\RelatorioComputadores.csv)"
        if (-not $caminho.EndsWith(".csv")) {
            $caminho += ".csv"
        }

        $computadores = Get-ADComputer -Filter * -SearchBase $OU | Select-Object Name, OperatingSystem
        $computadores | Export-Csv -Path $caminho -NoTypeInformation
        Write-Host "Relatório de computadores exportado com sucesso para $caminho!" -ForegroundColor Green
    }
    catch {
        Write-Host "Erro: $_" -ForegroundColor Red
    }
    finally {
        Start-Sleep -Seconds 2
    }
}

# Função principal
Menu
