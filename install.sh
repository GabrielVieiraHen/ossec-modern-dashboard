#!/bin/bash

# Cores para output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}=====================================================${NC}"
echo -e "${BLUE}   INSTALADOR AUTOMÁTICO - OSSEC MODERN DASHBOARD    ${NC}"
echo -e "${BLUE}=====================================================${NC}"

# 1. Verificar se é Root
if [ "$EUID" -ne 0 ]; then
  echo "❌ Por favor, execute como root (use sudo ./install.sh)"
  exit
fi

# 2. Instalar Dependências do Sistema
echo -e "${GREEN}[+] Atualizando sistema e instalando dependências...${NC}"
apt-get update -qq
apt-get install -y python3 python3-pip git ufw -qq

# 3. Definir diretório de instalação
INSTALL_DIR="/opt/ossec-dashboard"
REPO_URL="https://github.com/GabrielVieiraHen/ossec-modern-dashboard.git"

# 4. Baixar o Projeto
if [ -d "$INSTALL_DIR" ]; then
    echo -e "${GREEN}[+] Atualizando instalação existente em $INSTALL_DIR...${NC}"
    cd $INSTALL_DIR
    git pull
else
    echo -e "${GREEN}[+] Baixando o projeto para $INSTALL_DIR...${NC}"
    git clone $REPO_URL $INSTALL_DIR
    cd $INSTALL_DIR
fi

# 5. Instalar Dependências Python
echo -e "${GREEN}[+] Instalando bibliotecas Python...${NC}"
# Usa --break-system-packages para Ubuntu 23.04+ ou instala normal
pip3 install -r requirements.txt --break-system-packages 2>/dev/null || pip3 install -r requirements.txt

# 6. Configurar Permissões SUDO (Seguro)
# Cria um arquivo separado em /etc/sudoers.d em vez de editar o arquivo principal
echo -e "${GREEN}[+] Configurando permissões do OSSEC...${NC}"
SUDO_FILE="/etc/sudoers.d/ossec-dashboard"
echo "root ALL=(ALL) NOPASSWD: /var/ossec/bin/agent_control" > $SUDO_FILE
echo "root ALL=(ALL) NOPASSWD: /var/ossec/bin/ossec-control" >> $SUDO_FILE
chmod 0440 $SUDO_FILE

# 7. Configurar Firewall
echo -e "${GREEN}[+] Configurando Firewall (UFW)...${NC}"
ufw allow 5000/tcp > /dev/null
ufw allow 1514/udp > /dev/null
# Não recarregamos para não desconectar SSH se estiver remoto, mas garantimos a regra

# 8. Criar Serviço Systemd (Para rodar em segundo plano e iniciar no boot)
echo -e "${GREEN}[+] Criando serviço de inicialização automática...${NC}"
SERVICE_FILE="/etc/systemd/system/ossec-dashboard.service"

cat <<EOT > $SERVICE_FILE
[Unit]
Description=OSSEC Modern Dashboard Web Interface
After=network.target

[Service]
User=root
WorkingDirectory=$INSTALL_DIR
ExecStart=/usr/bin/python3 $INSTALL_DIR/app.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOT

# 9. Ativar e Iniciar o Serviço
systemctl daemon-reload
systemctl enable ossec-dashboard
systemctl restart ossec-dashboard

# 10. Finalização
IP_ADDRESS=$(hostname -I | awk '{print $1}')
echo -e "${BLUE}=====================================================${NC}"
echo -e "${GREEN}✅ INSTALAÇÃO CONCLUÍDA COM SUCESSO!${NC}"
echo -e "${BLUE}=====================================================${NC}"
echo -e "O dashboard já está rodando em segundo plano."
echo -e "Acesse agora em:"
echo -e "   ➡️  http://$IP_ADDRESS:5000/dashboard"
echo -e "   ➡️  http://localhost:5000/dashboard"
echo -e ""
echo -e "Para ver o status do serviço: sudo systemctl status ossec-dashboard"
echo -e "Para parar: sudo systemctl stop ossec-dashboard"
