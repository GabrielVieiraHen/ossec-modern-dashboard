from flask import Flask, jsonify, send_from_directory, request
from flask_cors import CORS
import json
import os
import subprocess
from datetime import datetime
import re
import socket

app = Flask(__name__)
CORS(app)

# --- Configurações OSSEC ---
OSSEC_DIR = "/var/ossec"
AGENTS_FILE = f"{OSSEC_DIR}/etc/client.keys"
ALERTS_LOG_PATH = f"{OSSEC_DIR}/logs/alerts/alerts.log"
# NOVA CONFIGURAÇÃO: Pasta raiz dos logs históricos
ALERTS_HISTORY_DIR = f"{OSSEC_DIR}/logs/alerts"

# Caminhos dos binários (COM SUDO)
AGENT_CONTROL = f"sudo {OSSEC_DIR}/bin/agent_control"
OSSEC_CONTROL = f"sudo {OSSEC_DIR}/bin/ossec-control"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# --- FUNÇÕES UTILITÁRIAS ---

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

def safe_file_read(filepath):
    try:
        if os.path.exists(filepath) and os.access(filepath, os.R_OK):
            # errors='ignore' é importante para logs com caracteres estranhos
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                return f.read(), None
        else:
            return None, f"Arquivo não existe ou sem permissão: {filepath}"
    except Exception as e:
        return None, f"Erro ao ler arquivo: {str(e)}"

def is_safe_path(basedir, path, follow_symlinks=True):
    """Garante que o caminho solicitado está dentro da pasta permitida."""
    if follow_symlinks:
        matchpath = os.path.realpath(path)
    else:
        matchpath = os.path.abspath(path)
    return basedir == os.path.commonpath((basedir, matchpath))

def run_ossec_command(command_string):
    try:
        result = subprocess.run(command_string, 
                              shell=True,
                              capture_output=True, 
                              text=True, 
                              timeout=10)
        if result.returncode != 0:
            return None, result.stderr
        return result.stdout, None
    except Exception as e:
        return None, str(e)

# --- FUNÇÕES DE DADOS OSSEC ---

def get_agents_data():
    agents = []
    stdout, error = run_ossec_command(f"{AGENT_CONTROL} -l")
    if stdout:
        for line in stdout.split('\n'):
            if 'ID:' in line and 'Name:' in line:
                parts = line.split(',')
                try:
                    agent_id = parts[0].split(':')[1].strip()
                    agent_name = parts[1].split(':')[1].strip().split(' ')[0]
                    agent_ip = parts[2].split(':')[1].strip()
                    status = "Active" if "Active" in line else "Disconnected"
                    if "Never connected" in line: status = "Never connected"
                    if "Local" in line: status = "Active"
                    agents.append({"id": agent_id, "name": agent_name, "ip": agent_ip, "status": status})
                except Exception: continue 
        return agents
    return [{"id": "000", "name": "local-server", "ip": "127.0.0.1", "status": "Active"}]

def get_ossec_status():
    services = {}
    stdout, error = run_ossec_command(f"{OSSEC_CONTROL} status")
    if stdout:
        for line in stdout.split('\n'):
            if 'is running' in line: services[line.split()[0]] = "running"
            elif 'not running' in line: services[line.split()[0]] = "stopped"
    if not services: return {"ossec-analysisd": "unknown", "ossec-remoted": "unknown"}
    return services

def parse_alert_log_block(block):
    try:
        alert = {
            "timestamp": datetime.now().isoformat(),
            "agent": {"name": "unknown"},
            "rule": {"id": "000", "level": 0, "description": "N/A"},
            "full_log": block.strip() 
        }
        ts_match = re.search(r'(\d{4} \w{3} \d{2} \d{2}:\d{2}:\d{2})', block)
        if ts_match:
            try: alert["timestamp"] = datetime.strptime(ts_match.group(1), '%Y %b %d %H:%M:%S').isoformat()
            except: pass

        rule_match = re.search(r'Rule: (\d+) \(level (\d+)\) -> \'(.*?)\'', block)
        if rule_match:
            alert["rule"] = {"id": rule_match.group(1), "level": int(rule_match.group(2)), "description": rule_match.group(3)}

        agent_match_1 = re.search(r'\(([^)]+)\)\s[\d\.]*->', block)
        agent_match_2 = re.search(r'Agent: \((.*?)\)', block)
        agent_match_3 = re.search(r'\s([^\s]+)->', block)

        if agent_match_1: alert["agent"]["name"] = agent_match_1.group(1).strip()
        elif agent_match_2: alert["agent"]["name"] = agent_match_2.group(1).strip()
        elif agent_match_3:
            raw_name = agent_match_3.group(1).replace('(', '').replace(')', '')
            if not re.match(r'^\d{1,3}\.', raw_name): alert["agent"]["name"] = raw_name
        else:
            if "ossec" in block.lower() and "ossec-server" not in block: alert["agent"]["name"] = "manager-local"
        return alert
    except Exception: return None

def get_alerts_data_optimized(max_alerts=100):
    alerts = []
    content, error = safe_file_read(ALERTS_LOG_PATH)
    if content:
        alert_blocks = content.split('** Alert')[1:]
        for block in reversed(alert_blocks):
            if len(alerts) >= max_alerts: break
            if not block.strip(): continue
            parsed_alert = parse_alert_log_block(block)
            if parsed_alert: alerts.append(parsed_alert)
        if alerts: return alerts, None
    if error: return [], f"Erro: {error}"
    return [], "Nenhum alerta encontrado."

# --- ROTAS DA API ---

@app.route('/')
def home():
    return jsonify({"status": "success", "message": "OSSEC API Online"})

@app.route('/api/status')
def api_status():
    return jsonify({"status": "success", "services": get_ossec_status()})

@app.route('/api/agents')
def get_agents():
    return jsonify({"status": "success", "agents": get_agents_data()})

@app.route('/api/alerts')
def get_alerts():
    try:
        agent_filter = request.args.get('agent', 'all')
        level_filter = request.args.get('level', 'all')
        attack_filter = request.args.get('attack', 'all')
        
        alerts, error = get_alerts_data_optimized(100)
        if error: return jsonify({"status": "error", "message": error})
        
        filtered_alerts = []
        level_map = {'low': (1, 3), 'medium': (4, 7), 'high': (8, 12), 'critical': (13, 20)}
        attack_patterns = {
            'ssh': ['ssh', 'sshd'], 'web': ['http', 'apache', 'nginx', 'web', '404', '403'],
            'bruteforce': ['failed password', 'brute force', 'authentication failure'],
            'malware': ['virus', 'malware', 'trojan', 'rootkit'],
            'system': ['systemd', 'sudo', 'root'], 'windows': ['windows', 'logon', 'logoff', 'user']
        }

        for alert in alerts:
            if agent_filter != 'all' and alert["agent"]["name"].lower() != agent_filter.lower(): continue
            if level_filter != 'all' and level_filter in level_map:
                min_l, max_l = level_map[level_filter]
                if not (min_l <= alert['rule']['level'] <= max_l): continue
            if attack_filter != 'all' and attack_filter in attack_patterns:
                full_text = (alert['full_log'] + alert['rule']['description']).lower()
                if not any(p in full_text for p in attack_patterns[attack_filter]): continue
            filtered_alerts.append(alert)
        return jsonify({"status": "success", "alerts": filtered_alerts, "count": len(filtered_alerts)})
    except Exception as e: return jsonify({"status": "error", "message": str(e)})

@app.route('/api/stats')
def get_stats():
    agents = get_agents_data()
    alerts, _ = get_alerts_data_optimized(100)
    if alerts is None: alerts = []
    return jsonify({
        "status": "success",
        "stats": {
            "total_agents": len(agents), "active_agents": len([a for a in agents if a['status'] == 'Active']),
            "alerts_today": len(alerts), "critical_alerts": len([a for a in alerts if a['rule']['level'] >= 10])
        }
    })

# --- NOVAS ROTAS PARA O EXPLORADOR DE LOGS ---

@app.route('/api/logs/list')
def list_logs():
    """Lista pastas e arquivos dentro do diretório de logs históricos."""
    req_path = request.args.get('path', '')
    
    # Cria o caminho completo
    abs_path = os.path.join(ALERTS_HISTORY_DIR, req_path)
    
    # SEGURANÇA: Verifica se não estão tentando sair da pasta de logs
    if not is_safe_path(ALERTS_HISTORY_DIR, abs_path):
        return jsonify({"status": "error", "message": "Acesso negado: Caminho inválido"}), 403
        
    if not os.path.exists(abs_path):
        return jsonify({"status": "error", "message": "Diretório não encontrado"}), 404

    items = []
    try:
        # Lista diretórios primeiro, depois arquivos
        with os.scandir(abs_path) as it:
            for entry in it:
                if entry.name.startswith('.'): continue # Ignora arquivos ocultos
                items.append({
                    "name": entry.name,
                    "type": "directory" if entry.is_dir() else "file",
                    "path": os.path.join(req_path, entry.name)
                })
        # Ordena: Pastas primeiro, depois arquivos. Ordem alfabética.
        items.sort(key=lambda x: (x['type'] != 'directory', x['name']))
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})
        
    return jsonify({"status": "success", "current_path": req_path, "items": items})

@app.route('/api/logs/content')
def get_log_content():
    """Lê o conteúdo de um arquivo de log específico."""
    req_path = request.args.get('path', '')
    abs_path = os.path.join(ALERTS_HISTORY_DIR, req_path)
    
    if not is_safe_path(ALERTS_HISTORY_DIR, abs_path):
        return jsonify({"status": "error", "message": "Acesso negado"}), 403
        
    content, error = safe_file_read(abs_path)
    if error:
        return jsonify({"status": "error", "message": error})
        
    return jsonify({"status": "success", "content": content})

# --- ROTAS DE FRONTEND ---

@app.route('/dashboard')
def serve_dashboard():
    return send_from_directory(BASE_DIR, 'index.html')

@app.route('/logs') # Nova rota para a página de logs
def serve_logs_page():
    return send_from_directory(BASE_DIR, 'logs.html')

@app.route('/<path:path>')
def serve_static(path):
    return send_from_directory(BASE_DIR, path)

if __name__ == '__main__':
    local_ip = get_local_ip()
    print(f"🚀 API OSSEC RODANDO EM: http://{local_ip}:5000/dashboard")
    app.run(host='0.0.0.0', port=5000, debug=False)