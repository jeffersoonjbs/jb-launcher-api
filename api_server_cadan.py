# API_Jefferson

import mysql.connector
from flask import Flask, request, jsonify, send_from_directory
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import date
import os
import sys
import shutil
from waitress import serve
import json
import time

app = Flask(__name__)

# ==============================================================================
# CONFIGURAÇÃO DO BANCO DE DADOS
# ==============================================================================
DB_CONFIG = {
    'user': 'jefferson',
    'password': '8825',
    'host': 'localhost',
    'database': 'base'
}

# Diretório onde seus EXEs estão no SERVIDOR.
DIRETORIO_DOS_EXE_SERVIDOR = r"C:\Users\JEFFCONTABIL\Documents\BASE\Base_exe"

# ==============================================================================
# FUNÇÕES AUXILIARES
# ==============================================================================

def get_db_connection():
    """Cria e retorna uma conexão com o MySQL."""
    try:
        return mysql.connector.connect(**DB_CONFIG)
    except mysql.connector.Error as err:
        print(f"Erro ao conectar ao DB: {err}", file=sys.stderr)
        return None
    except Exception as e:
        print(f"Erro inesperado ao conectar ao DB: {e}", file=sys.stderr)
        return None

def buscar_executaveis(diretorio):
    """
    Retorna um dicionário com detalhes dos executáveis, usando o timestamp 
    do arquivo como 'versão'.
    """
    if not os.path.isdir(diretorio):
        print(f"ERRO CRÍTICO: Diretório do servidor não encontrado/inválido: {diretorio}", file=sys.stderr)
        return None

    executaveis = {}
    try:
        for nome_arquivo in os.listdir(diretorio):
            caminho_completo = os.path.join(diretorio, nome_arquivo)
            
            if nome_arquivo.lower().endswith(".exe") and os.path.isfile(caminho_completo):
                timestamp_modificacao = os.path.getmtime(caminho_completo)
                nome_base = nome_arquivo[:-4]
                nome_limpo = nome_base.replace("_", " ").upper()
                
                executaveis[nome_limpo] = {
                    "exe": nome_arquivo,
                    "versao": str(timestamp_modificacao) 
                }
                
    except PermissionError:
        print(f"ERRO DE PERMISSÃO: O serviço não consegue ler o diretório: {diretorio}", file=sys.stderr)
        return None
    except Exception as e:
        print(f"ERRO: Falha inesperada ao listar arquivos: {e}", file=sys.stderr)
        return None
            
    return dict(sorted(executaveis.items()))

# ==============================================================================
# ENDPOINT: LISTAR PROGRAMAS DISPONÍVEIS
# ==============================================================================
@app.route('/api/list_programs', methods=['GET'])
def list_programs():
    """Lê a pasta de programas e retorna a lista de executáveis."""
    program_list = buscar_executaveis(DIRETORIO_DOS_EXE_SERVIDOR)
    
    if program_list is None:
        return jsonify({"status": "erro", "mensagem": "Falha ao ler diretório de executáveis no servidor."}), 500
        
    return jsonify({
        "status": "ok",
        "programas_servidor": program_list 
    })

# ==============================================================================
# ENDPOINT DE LOGIN
# ==============================================================================
@app.route('/api/login', methods=['POST'])
def login():
    """Valida credenciais e retorna o status da licença."""
    data = request.get_json()
    usuario = data.get('usuario')
    senha = data.get('senha')

    if not usuario or not senha:
        return jsonify({"status": "erro", "mensagem": "Usuário e senha são obrigatórios."}), 400

    conn = None
    try:
        conn = get_db_connection()
        if not conn:
             return jsonify({"status": "erro", "mensagem": "Falha ao conectar ao Banco de Dados."}), 500

        cursor = conn.cursor(dictionary=True)
        query = "SELECT username, password_hash, is_active, is_admin, expiration_date, allowed_apps FROM licenses WHERE username = %s"
        cursor.execute(query, (usuario,))
        user_record = cursor.fetchone()
        cursor.close()

        if not user_record:
            return jsonify({"status": "erro", "mensagem": "Usuário não encontrado."}), 401
        
        if not check_password_hash(user_record['password_hash'], senha):
            return jsonify({"status": "erro", "mensagem": "Senha inválida."}), 401

        if not user_record['is_active']:
            return jsonify({"status": "erro", "mensagem": "Licença inativa. Contate o suporte."}), 403
        
        if user_record['expiration_date'] and user_record['expiration_date'] < date.today():
             return jsonify({"status": "erro", "mensagem": "Licença expirada."}), 403

        # Lógica de Permissões
        allowed_apps_db_string = user_record['allowed_apps']
        allowed_apps_list = []
        program_list_full = buscar_executaveis(DIRETORIO_DOS_EXE_SERVIDOR) 
        
        if program_list_full is None:
             return jsonify({"status": "erro", "mensagem": "Erro interno: Servidor falhou ao listar programas."}), 500

        if allowed_apps_db_string:
            if allowed_apps_db_string.strip() == '*':
                allowed_apps_list = list(program_list_full.keys())
            else:
                raw_apps = allowed_apps_db_string.split(',')
                # Normaliza para maiúsculo e remove extensão .exe se houver
                normalized_inputs = []
                for app in raw_apps:
                    clean = app.strip().upper().replace(".EXE", "")
                    normalized_inputs.append(clean)
                
                # Compara com as chaves (que já são UPPERCASE)
                allowed_apps_list = [app for app in normalized_inputs if app in program_list_full]

        return jsonify({
            "status": "ok",
            "message": "Login bem-sucedido.",
            "is_admin": user_record.get('is_admin', 0),
            "expira_em": user_record['expiration_date'].strftime('%d/%m/%Y') if user_record['expiration_date'] else "Vitalícia",
            "programas_permitidos": allowed_apps_list
        })

    except Exception as e:
        print(f"Erro geral no Login: {e}", file=sys.stderr)
        return jsonify({"status": "erro", "mensagem": f"Erro interno: {str(e)}"}), 500
    finally:
        if conn and conn.is_connected(): conn.close()

# ==============================================================================
# ENDPOINT DE DOWNLOAD CONTROLADO
# ==============================================================================
@app.route('/api/download/<filename>', methods=['GET'])
def download_programa(filename):
    """Permite que o cliente baixe um executável específico."""
    if not filename.lower().endswith('.exe'):
        return jsonify({"status": "erro", "mensagem": "Formato de arquivo não permitido."}), 400

    try:
        return send_from_directory(
            DIRETORIO_DOS_EXE_SERVIDOR,
            filename,
            as_attachment=True
        )
    except FileNotFoundError:
        return jsonify({"status": "erro", "mensagem": f"Arquivo '{filename}' não encontrado."}), 404
    except Exception as e:
        print(f"Erro ao servir arquivo: {e}", file=sys.stderr)
        return jsonify({"status": "erro", "mensagem": "Erro interno."}), 500

# ==============================================================================
# ENDPOINTS ADMINISTRATIVOS
# ==============================================================================

@app.route('/api/admin/list_users', methods=['GET'])
def admin_list_users():
    """Lista todos os usuários."""
    conn = None
    try:
        conn = get_db_connection()
        if not conn:
            return jsonify({"status": "erro", "mensagem": "Falha ao conectar ao DB."}), 500
        
        cursor = conn.cursor(dictionary=True)
        query = "SELECT username, is_active, is_admin, expiration_date, allowed_apps FROM licenses"
        cursor.execute(query)
        users = cursor.fetchall()
        cursor.close()
        
        for user in users:
            if user['expiration_date']:
                user['expiration_date'] = user['expiration_date'].strftime('%d-%m-%Y')
            else:
                user['expiration_date'] = None
        
        return jsonify({"status": "ok", "users": users})
    except Exception as e:
        print(f"Erro ao listar usuários: {e}", file=sys.stderr)
        return jsonify({"status": "erro", "mensagem": f"Erro interno: {str(e)}"}), 500
    finally:
        if conn and conn.is_connected(): conn.close()

@app.route('/api/admin/create_user', methods=['POST'])
def admin_create_user():
    """Cria um novo usuário."""
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    is_admin = data.get('is_admin', 0)
    allowed_apps = data.get('allowed_apps', '*')
    expiration_days = data.get('expiration_days')
    
    if not username or not password:
        return jsonify({"status": "erro", "mensagem": "Usuário e senha obrigatórios."}), 400
    
    conn = None
    try:
        conn = get_db_connection()
        if not conn:
            return jsonify({"status": "erro", "mensagem": "Falha DB."}), 500
        
        if expiration_days and expiration_days > 0:
            from datetime import timedelta
            exp_date = (date.today() + timedelta(days=expiration_days)).strftime('%Y-%m-%d')
        else:
            exp_date = None
        
        password_hash = generate_password_hash(password)
        
        cursor = conn.cursor()
        query = """INSERT INTO licenses 
                   (username, password_hash, is_active, is_admin, expiration_date, allowed_apps) 
                   VALUES (%s, %s, 1, %s, %s, %s)"""
        cursor.execute(query, (username, password_hash, is_admin, exp_date, allowed_apps))
        conn.commit()
        cursor.close()
        
        return jsonify({"status": "ok", "mensagem": f"Usuário '{username}' criado."})
    
    except mysql.connector.IntegrityError:
        return jsonify({"status": "erro", "mensagem": "Usuário já existe."}), 400
    except Exception as e:
        print(f"Erro ao criar: {e}", file=sys.stderr)
        return jsonify({"status": "erro", "mensagem": f"Erro: {str(e)}"}), 500
    finally:
        if conn and conn.is_connected(): conn.close()

@app.route('/api/admin/edit_permissions', methods=['POST'])
def admin_edit_permissions():
    """Edita permissões."""
    data = request.get_json()
    target_username = data.get('target_username')
    allowed_apps = data.get('allowed_apps')
    
    if not target_username or not allowed_apps:
        return jsonify({"status": "erro", "mensagem": "Dados inválidos."}), 400
    
    conn = None
    try:
        conn = get_db_connection()
        if not conn: return jsonify({"status": "erro", "mensagem": "Falha DB."}), 500
        
        cursor = conn.cursor()
        query = "UPDATE licenses SET allowed_apps = %s WHERE username = %s"
        cursor.execute(query, (allowed_apps, target_username))
        conn.commit()
        cursor.close()
        
        return jsonify({"status": "ok", "mensagem": "Atualizado."})
    except Exception as e:
        print(f"Erro perm: {e}", file=sys.stderr)
        return jsonify({"status": "erro", "mensagem": str(e)}), 500
    finally:
        if conn and conn.is_connected(): conn.close()

@app.route('/api/admin/change_password', methods=['POST'])
def admin_change_password():
    """Altera senha."""
    data = request.get_json()
    target_username = data.get('target_username')
    new_password = data.get('new_password')
    
    if not target_username or not new_password:
        return jsonify({"status": "erro", "mensagem": "Dados inválidos."}), 400
    
    conn = None
    try:
        conn = get_db_connection()
        if not conn: return jsonify({"status": "erro", "mensagem": "Falha DB."}), 500
        
        password_hash = generate_password_hash(new_password)
        cursor = conn.cursor()
        query = "UPDATE licenses SET password_hash = %s WHERE username = %s"
        cursor.execute(query, (password_hash, target_username))
        conn.commit()
        cursor.close()
        
        return jsonify({"status": "ok", "mensagem": "Senha alterada."})
    except Exception as e:
        print(f"Erro senha: {e}", file=sys.stderr)
        return jsonify({"status": "erro", "mensagem": str(e)}), 500
    finally:
        if conn and conn.is_connected(): conn.close()

# ==============================================================================
# ENDPOINTS ADICIONAIS
# ==============================================================================

@app.route('/api/admin/delete_user', methods=['POST'])
def admin_delete_user():
    """Exclui um usuário (somente para admins)."""
    data = request.get_json()
    target_username = data.get('target_username')
    
    if not target_username:
        return jsonify({"status": "erro", "mensagem": "Usuário obrigatório."}), 400
    
    conn = None
    try:
        conn = get_db_connection()
        if not conn: return jsonify({"status": "erro", "mensagem": "Falha DB."}), 500
        
        cursor = conn.cursor()
        query = "DELETE FROM licenses WHERE username = %s"
        cursor.execute(query, (target_username,))
        conn.commit()
        
        if cursor.rowcount == 0:
            cursor.close()
            return jsonify({"status": "erro", "mensagem": "Usuário não encontrado."}), 404
        
        cursor.close()
        return jsonify({"status": "ok", "mensagem": "Usuário excluído."})
    except Exception as e:
        print(f"Erro delete: {e}", file=sys.stderr)
        return jsonify({"status": "erro", "mensagem": str(e)}), 500
    finally:
        if conn and conn.is_connected(): conn.close()

@app.route('/api/admin/toggle_status', methods=['POST'])
def admin_toggle_status():
    """Alterna status ativo/inativo."""
    data = request.get_json()
    target_username = data.get('target_username')
    
    if not target_username:
        return jsonify({"status": "erro", "mensagem": "Usuário obrigatório."}), 400
    
    conn = None
    try:
        conn = get_db_connection()
        if not conn: return jsonify({"status": "erro", "mensagem": "Falha DB."}), 500
        
        cursor = conn.cursor()
        # Primeiro busca status atual
        cursor.execute("SELECT is_active FROM licenses WHERE username = %s", (target_username,))
        result = cursor.fetchone()
        
        if not result:
            cursor.close()
            return jsonify({"status": "erro", "mensagem": "Usuário não encontrado."}), 404
            
        # Inverte status (se 1 vira 0, se 0 vira 1)
        new_status = 0 if result[0] else 1
        
        cursor.execute("UPDATE licenses SET is_active = %s WHERE username = %s", (new_status, target_username))
        conn.commit()
        cursor.close()
        
        status_str = "Ativo" if new_status else "Inativo"
        return jsonify({"status": "ok", "mensagem": f"Status alterado para {status_str}."})
    except Exception as e:
        print(f"Erro toggle: {e}", file=sys.stderr)
        return jsonify({"status": "erro", "mensagem": str(e)}), 500
    finally:
        if conn and conn.is_connected(): conn.close()

# ==============================================================================
# INICIALIZAÇÃO COM VERIFICAÇÃO DE ESQUEMA
# ==============================================================================

def check_db_schema():
    print("🔄 Verificando esquema do banco (MySQL Connector)...")
    conn = None
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor()
        cursor.execute("SHOW COLUMNS FROM licenses LIKE 'is_admin'")
        if not cursor.fetchone():
            print("⚠️ Adicionando coluna 'is_admin'...")
            try:
                cursor.execute("ALTER TABLE licenses ADD COLUMN is_admin INTEGER DEFAULT 0")
                cursor.execute("CREATE INDEX idx_is_admin ON licenses(is_admin)")
                conn.commit()
                print("✅ Coluna 'is_admin' adicionada com sucesso.")
            except Exception as e:
                print(f"⚠️ Erro ao alterar tabela (pode já existir): {e}")
        cursor.close()
        print("✅ Esquema verificado.")
    except Exception as e:
        print(f"❌ Erro na verificação do esquema: {e}")
    finally:
        if conn and conn.is_connected(): conn.close()

if __name__ == '__main__':
    check_db_schema()
    print(f"🚀 Iniciando API na porta 5000...")
    serve(app, host='0.0.0.0', port=5000, threads=10)