# 🛡️ OSSEC Modern Dashboard

Um painel web moderno, responsivo e em tempo real para monitoramento do **OSSEC HIDS**.

Este projeto fornece uma interface visual amigável para gerenciar agentes, visualizar alertas de segurança com análise simplificada ("IA") e explorar logs históricos do servidor OSSEC.

## ✨ Funcionalidades

* **📊 Dashboard em Tempo Real:** Visualize alertas críticos, status dos agentes e estatísticas do dia.
* **🤖 Análise Inteligente:** O sistema analisa automaticamente logs brutos e fornece recomendações de ação (ex: "Bloquear IP", "Isolar Máquina").
* **🔍 Filtros Avançados:** Filtre por Nível de Alerta, Agente, Tipo de Ataque (SSH, Web, Brute Force, etc.).
* **📂 Explorador de Logs:** Navegue pelo histórico de logs do OSSEC (`archives.log` ou `alerts.log`) diretamente pelo navegador.
* **🖥️ Gerenciamento de Agentes:** Veja rapidamente quais agentes estão Online/Offline/Nunca Conectados.
* **⏸️ Modo Pausa:** Pause a atualização automática para analisar incidentes com calma.

## 🛠️ Pré-requisitos

* **OSSEC HIDS Manager** instalado e rodando (geralmente em `/var/ossec`).
* **Python 3.x**.
* Permissões de `sudo` para o usuário que executará o dashboard (para acessar os binários do OSSEC).

## 🚀 Instalação

1.  **Clone o repositório:**
    ```bash
    git clone [https://github.com/SEU_USUARIO/ossec-modern-dashboard.git](https://github.com/SEU_USUARIO/ossec-modern-dashboard.git)
    cd ossec-modern-dashboard
    ```

2.  **Instale as dependências:**
    ```bash
    pip3 install -r requirements.txt
    ```

3.  **Configure as Permissões (Crucial):**
    O script precisa executar comandos do OSSEC. Edite o arquivo sudoers:
    ```bash
    sudo visudo
    ```
    Adicione as seguintes linhas ao final do arquivo (substitua `seu_usuario` pelo seu usuário Linux):
    ```text
    seu_usuario ALL=(ALL) NOPASSWD: /var/ossec/bin/agent_control
    seu_usuario ALL=(ALL) NOPASSWD: /var/ossec/bin/ossec-control
    ```

4.  **Ajuste o Firewall (UFW):**
    Libere a porta 5000 para o Dashboard e a 1514 para os agentes OSSEC.
    ```bash
    sudo ufw allow 5000/tcp
    sudo ufw allow 1514/udp
    ```

## ▶️ Como Usar

Inicie o servidor:

```bash
python3 app.py
