import ipaddress
import re
import html
import shlex
import paramiko
import xml.etree.ElementTree as ET

#Check target ip
def check_target(text):
    try:
        address = ipaddress.ip_address(text.strip())
    except ValueError:
        raise ValueError('Enter a valid IP address.')
    if address.version != 4 or not address.is_private:
        raise ValueError('Only authorized private IPv4 targets are allowed.')
    return str(address)

#Connects to the VM
def connect_ssh(vm_ip, username, password):
    connection = paramiko.SSHClient()
    connection.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    connection.connect(vm_ip, username=username, password=password, timeout=15,
                       auth_timeout=15, banner_timeout=15)
    return connection

#Checks for errors while running commands on the VM
def run_command(connection, command, timeout=360):
    stdin, stdout, stderr = connection.exec_command(command, timeout=timeout)
    output = stdout.read().decode('utf-8', errors='replace')
    error = stderr.read().decode('utf-8', errors='replace')
    status = stdout.channel.recv_exit_status()
    if status != 0:
        raise RuntimeError((error or output or 'Remote command failed').strip()[:500])
    return output

# Checks if target responds to a ping
def target_connected(connection, target):
    try:
        run_command(connection, 'ping -c 1 -W 2 ' + shlex.quote(target), timeout=5)
        return True
    except Exception:
        return False

# function to get web applications on open ports
def get_application(connection, target, port, title):
    bad_titles = ('404', '400', 'bad request', 'not found', 'http status',
                  'plain http', 'welcome', 'index of', "doesn't have a title",
                  'default page', 'forbidden', 'unauthorized')

    def clean_name(value):
        value = re.sub(r'<[^>]+>', ' ', value)
        value = html.unescape(value)
        value = re.sub(r'\s+', ' ', value).strip()
        if not value or any(word in value.lower() for word in bad_titles):
            return ''
        return value.replace('Login :: ', '')[:45]

    for protocol in ('http', 'https'):
        for path in ('/', '/login', '/admin'):
            url = protocol + '://' + target + ':' + port + path
            command = 'curl -ksfL --max-time 4 ' + shlex.quote(url)
            try:
                page = run_command(connection, command, timeout=7)
            except Exception:
                continue


            for pattern in (
                r'<meta[^>]*name=["\']application-name["\'][^>]*content=["\']([^"\']+)',
                r'<meta[^>]*name=["\']generator["\'][^>]*content=["\']([^"\']+)',
                r'<title[^>]*>(.*?)</title>',
                r'<h1[^>]*>(.*?)</h1>',
            ):
                match = re.search(pattern, page, re.I | re.S)
                if match:
                    application = clean_name(match.group(1))
                    if application:
                        return application

    return clean_name(title)

# Runs Nmap scan and gets open port information
def run_nmap(connection, target, ssh_password):

    command = ('nmap -sT -sV --version-all '
               '--script http-title,http-headers '
               '-Pn --open -p- -oX - ' + shlex.quote(target))
    output = run_command(connection, command, timeout=1800)
    root = ET.fromstring(output)
    host = root.find('host')
    if host is None:
        raise RuntimeError('Nmap returned no host information.')
    status = host.find('status')
    host_status = status.get('state', 'Unknown') if status is not None else 'Unknown'
    ports = []
    for port in root.findall('.//port'):
        state = port.find('state')
        if state is None or state.get('state') != 'open':
            continue
        service = port.find('service')
        version = ''
        name = 'unknown'
        if service is not None:
            name = service.get('name', 'unknown')
            version = ' '.join(part for part in [
                service.get('product', ''),
                service.get('version', ''),
                service.get('extrainfo', '')
            ] if part)

        port_number = port.get('portid', '')
        title = ''
        for script in port.findall('script'):
            if script.get('id') == 'http-title':
                title = script.get('output', '')

        application = ''

        non_web = ('ssh', 'smtp', 'mysql', 'postgresql', 'redis', 'mongod')
        if name not in non_web:
            application = get_application(connection, target, port_number, title)

        ports.append({'port': port_number + '/tcp', 'service': name,
                      'application': application, 'version': version,
                      'state': 'open'})


    command = ('sudo -S -p "" nmap -sU -sV -Pn --top-ports 100 '
               '--open -oX - ' + shlex.quote(target))
    stdin, stdout, stderr = connection.exec_command(command, timeout=1800)
    stdin.write(ssh_password + '\n')
    stdin.flush()
    output = stdout.read().decode('utf-8', errors='replace')
    error = stderr.read().decode('utf-8', errors='replace')
    if stdout.channel.recv_exit_status() != 0:
        raise RuntimeError('UDP scan failed: ' + error[:250])
    udp_root = ET.fromstring(output)
    for port in udp_root.findall('.//port'):
        state = port.find('state')
        if state is None or state.get('state') not in ('open', 'open|filtered'):
            continue
        service = port.find('service')
        name = service.get('name', 'unknown') if service is not None else 'unknown'
        version = ''
        if service is not None:
            version = ' '.join(x for x in (service.get('product', ''),
                                           service.get('version', '')) if x)
        ports.append({'port': port.get('portid', '') + '/udp',
                      'service': name, 'application': '',
                      'version': version, 'state': state.get('state')})
    return host_status, ports
