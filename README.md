
# Gerenciamento de Active Directory com PowerShell

Este projeto é um script em PowerShell que oferece uma interface menu-driven para gerenciar usuários, computadores e grupos no **Active Directory (AD)**. Ele foi desenvolvido para automatizar tarefas comuns de administração de AD, como criação de usuários, inativação de contas, reset de senhas, movimentação de objetos entre OUs, e muito mais.

---

## Funcionalidades

O script oferece as seguintes funcionalidades:

- **Criação de Usuários**: Cria usuários em massa a partir de um arquivo CSV ou TXT.
- **Inativação/Reativação de Contas**: Desabilita ou reativa contas de usuários.
- **Reset de Senhas**: Reseta a senha de um usuário.
- **Desbloqueio de Contas**: Desbloqueia contas de usuários.
- **Associação de Computadores**: Adiciona computadores ao domínio.
- **Movimentação de Objetos**: Move usuários ou computadores entre OUs.
- **Exportação de Relatórios**: Gera relatórios de usuários e computadores em formato CSV.
- **Gerenciamento de Grupos**: Adiciona ou remove usuários de grupos.
- **Sincronização do AD**: Executa a sincronização do Active Directory.

---

## Como Usar

### Pré-requisitos

- **PowerShell**: O script requer o PowerShell 5.1 ou superior.
- **Módulo ActiveDirectory**: Certifique-se de que o módulo do Active Directory está instalado.
  ```powershell
  Install-WindowsFeature -Name RSAT-AD-PowerShell
  ```

### Executando o Script

1. **Clone o Repositório**:
   ```bash
   git clone https://github.com/seu-usuario/seu-repositorio.git
   ```

2. **Execute o Script**:
   - Abra o PowerShell como administrador.
   - Navegue até o diretório do script.
   - Execute o script:
     ```powershell
     .\GerenciamentoAD.ps1
     ```

3. **Siga o Menu**:
   - O script exibirá um menu interativo com todas as opções disponíveis.
   - Escolha a opção desejada e siga as instruções.

---

## Estrutura do Projeto

- **GerenciamentoAD.ps1**: Script principal com o menu e todas as funcionalidades.
- **README.md**: Este arquivo, com a documentação do projeto.
- **Exemplos/**: Pasta com exemplos de arquivos CSV e TXT para criação de usuários.

---

## Exemplos de Uso

### Criando Usuários a Partir de um Arquivo CSV

1. Crie um arquivo CSV com os seguintes campos:
   ```csv
   NomeCompleto,Senha
   Carlos Eduardo Prado,Senha123
   Maria Souza Silva,Senha456
   ```

2. Execute o script e escolha a opção **1 - Criar usuário no AD**.
3. Forneça o caminho do arquivo CSV e a OU de destino.

### Inativando um Usuário

1. Execute o script e escolha a opção **2 - Inativar usuário no AD**.
2. Insira o nome do usuário que deseja inativar.

---

## Contribuindo

Contribuições são bem-vindas! Siga os passos abaixo:

1. Faça um fork do projeto.
2. Crie uma branch para sua feature (`git checkout -b feature/nova-feature`).
3. Commit suas mudanças (`git commit -m 'Adicionando nova feature'`).
4. Faça push para a branch (`git push origin feature/nova-feature`).
5. Abra um Pull Request.

---


---

## Contato

Se tiver dúvidas ou sugestões, sinta-se à vontade para entrar em contato:

- **Nome**: Carlos Eduardo Guimaraes Prado
- **Email**: carlospradopro@outlook.com
- **LinkedIn**: [Carlos Eduardo Prado]([https://www.linkedin.com/in/seu-linkedin](https://www.linkedin.com/in/carlos-eduardo-guimaraes-prado-88547a1b5/))

---

## Agradecimentos

- Inspirado em uma publicação de um colega de profissão Daniel Frade no LinkedIn.
- Adaptado e aprimorado para atender às necessidades da minha empresa.

---
