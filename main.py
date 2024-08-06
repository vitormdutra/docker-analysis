import paramiko
import pandas as pd
import re
import matplotlib.pyplot as plt

# Detalhes de conexão SSH
ssh_host = 'host_connection'
ssh_user = 'user_connection'
ssh_password = 'user_password'  # Substitua pela sua senha

# Nome do container Docker
container_name = 'container_name'

# Padrões de log para tentar combinar
log_patterns = [
    re.compile(
        r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3})\s+-(DEBUG|INFO|WARN|ERROR)\s+\d+\s+([^\s]+)\s+---\s+\[(.*?)\]\s+([^\s]+)\s+:\s+(.*)'),
    # Adicione mais padrões aqui conforme necessário
]

# Função para remover caracteres ANSI
def remove_ansi_escape_sequences(text):
    ansi_escape = re.compile(r'\x1b\[[0-9;]*m')
    return ansi_escape.sub('', text)

# Função para analisar uma linha do log
def parse_log_line(line):
    line = remove_ansi_escape_sequences(line)  # Remover caracteres ANSI
    for pattern in log_patterns:
        match = pattern.match(line)
        if match:
            return match.groups()
    return None

# Função para capturar logs de erro multilinha (exemplo de Java stack trace)
def capture_multiline_logs(log_lines):
    multiline_log = []
    is_multiline = False
    for line in log_lines:
        if "Exception" in line or "Error" in line:
            is_multiline = True
            multiline_log.append(line)
        elif is_multiline and (line.startswith("\tat ") or line.strip() == ""):
            multiline_log.append(line)
        else:
            is_multiline = False
            if multiline_log:
                yield ' '.join(multiline_log)
                multiline_log = []

# Estabelecer conexão SSH
client = paramiko.SSHClient()
client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

try:
    # Conectar usando senha
    client.connect(ssh_host, username=ssh_user, password=ssh_password)

    # Executar comando para capturar logs do container
    stdin, stdout, stderr = client.exec_command(f'docker logs {container_name}')

    # Capturar logs tanto de stdout quanto de stderr
    log_lines = stdout.readlines() + stderr.readlines()
    print("Primeiras linhas de log capturadas:")
    print(log_lines[:5])  # Exibe as primeiras 5 linhas de log

    # Analisar logs e capturar logs multilinha
    log_data = [parse_log_line(line) for line in log_lines if parse_log_line(line) is not None]
    multiline_logs = list(capture_multiline_logs(log_lines))

    # Imprimir logs multilinha
    if multiline_logs:
        print("Logs multilinha capturados:")
        for log in multiline_logs:
            print(log)

    # Criar DataFrame
    if log_data:
        columns = ['timestamp', 'level', 'thread', 'logger', 'logger_class', 'message']
        df = pd.DataFrame(log_data, columns=columns)

        # Converter timestamp para datetime
        if 'timestamp' in df.columns:
            try:
                df['timestamp'] = pd.to_datetime(df['timestamp'], format='%Y-%m-%d %H:%M:%S.%f')
            except Exception as e:
                print(f"Erro ao converter timestamp: {e}")

        # Analisar logs por nível
        if 'timestamp' in df.columns and not df.empty:
            logs_by_level = df.groupby('level').size()

            # Visualizar logs por nível
            if not logs_by_level.empty:
                plt.figure(figsize=(10, 6))
                logs_by_level.plot(kind='bar', title='Logs por Nível')
                plt.xlabel('Nível')
                plt.ylabel('Número de Logs')
                plt.show()
            else:
                print("Nenhum dado para plotar.")

            # Analisar logs por minuto
            logs_by_minute = df.set_index('timestamp').resample('min').size()

            # Criar DataFrame de logs por minuto
            logs_by_minute_df = logs_by_minute.reset_index()
            logs_by_minute_df.columns = ['timestamp', 'count']

            # Visualizar logs por minuto
            plt.figure(figsize=(10, 6))
            ax = logs_by_minute.plot(title='Logs por Minuto')
            plt.xlabel('Tempo')
            plt.ylabel('Número de Logs')
            if len(logs_by_minute) == 1:
                ax.set_xlim(logs_by_minute.index[0] - pd.Timedelta(minutes=1),
                            logs_by_minute.index[0] + pd.Timedelta(minutes=1))
            plt.show()

            # Exibir DataFrame de logs por minuto
            print("\nDataFrame de Logs por Minuto:")
            print(logs_by_minute_df)

            # Analisar logs por dia
            logs_by_day = df.set_index('timestamp').resample('D').size()

            # Criar DataFrame de logs por dia
            logs_by_day_df = logs_by_day.reset_index()
            logs_by_day_df.columns = ['date', 'count']

            # Visualizar logs por dia
            plt.figure(figsize=(10, 6))
            ax = logs_by_day.plot(title='Logs por Dia')
            plt.xlabel('Data')
            plt.ylabel('Número de Logs')
            if len(logs_by_day) == 1:
                ax.set_xlim(logs_by_day.index[0] - pd.Timedelta(days=1),
                            logs_by_day.index[0] + pd.Timedelta(days=1))
            plt.show()

            # Exibir DataFrame de logs por dia
            print("\nDataFrame de Logs por Dia:")
            print(logs_by_day_df)
        else:
            print("O DataFrame está vazio ou não tem coluna de timestamp.")
    else:
        print("Nenhum dado para analisar.")

finally:
    # Fechar a conexão SSH
    client.close()
