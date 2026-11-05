import shlex
import time
import xml.etree.ElementTree as ET

#for the openVAS scans
FULL_AND_FAST = '31aecbae-e999-4c7d-ba29-07d11b9b0eaf'
PORT_LIST = '730ef368-57e2-11e1-a90f-406186ea4fc5'
SCANNER = '08b69003-5fc2-4037-a479-93b440211c73'

# OpenVAS commands for VM
def gvm_command(connection, ssh_password, gvm_password, xml):
    command = ('sudo -S -p "" -u _gvm gvm-cli '
               '--gmp-username admin --gmp-password ' + shlex.quote(gvm_password) +
               ' socket --socketpath /run/gvmd/gvmd.sock --xml ' + shlex.quote(xml))
    stdin, stdout, stderr = connection.exec_command(command, timeout=120)
    stdin.write(ssh_password + '\n')
    stdin.flush()
    stdin.channel.shutdown_write()
    output = stdout.read().decode('utf-8', errors='replace')
    error = stderr.read().decode('utf-8', errors='replace')
    if stdout.channel.recv_exit_status() != 0:
        raise RuntimeError('OpenVAS command failed: ' + (error or output).strip()[:350])
    try:
        root = ET.fromstring(output.strip())
    except ET.ParseError:
        raise RuntimeError('OpenVAS did not return valid scan data: ' + output[:200])
    code = root.get('status', '200')
    if not code.startswith('2'):
        raise RuntimeError('OpenVAS: ' + root.get('status_text', 'Request failed'))
    return root

# Starts openVAS scan
def start_scan(connection, ssh_password, gvm_password, target):
    target_xml = ('<create_target><name>ASM ' + target + ' ' + str(int(time.time())) +
                  '</name><hosts>' + target + '</hosts>' +
                  '<port_list id="' + PORT_LIST + '"/>' +
                  '<alive_tests>Consider Alive</alive_tests></create_target>')
    created = gvm_command(connection, ssh_password, gvm_password, target_xml)
    target_id = created.get('id')
    if not target_id:
        raise RuntimeError('OpenVAS did not create a target.')
    task_xml = ('<create_task><name>ASM Scan ' + target + '</name>' +
                '<target id="' + target_id + '"/>' +
                '<config id="' + FULL_AND_FAST + '"/>' +
                '<scanner id="' + SCANNER + '"/></create_task>')
    created_task = gvm_command(connection, ssh_password, gvm_password, task_xml)
    task_id = created_task.get('id')
    if not task_id:
        raise RuntimeError('OpenVAS did not create a scan task.')
    started = gvm_command(connection, ssh_password, gvm_password,
                          '<start_task task_id="' + task_id + '"/>')
    report_id = started.findtext('report_id')
    if not report_id:
        raise RuntimeError('OpenVAS did not start the scan.')
    return task_id, report_id

# checks progress of openVAS scan
def scan_status(connection, ssh_password, gvm_password, task_id):
    root = gvm_command(connection, ssh_password, gvm_password,
                       '<get_tasks task_id="' + task_id + '"/>')
    return (root.findtext('.//task/status', default='Unknown'),
            root.findtext('.//task/progress', default=''))

# Gets results from openVAS scan
def get_results(connection, ssh_password, gvm_password, report_id):

    report_xml = ('<get_reports report_id="' + report_id + '" details="1" '
                  'filter="rows=-1 min_qod=0 levels=hmlg"/>')
    root = gvm_command(connection, ssh_password, gvm_password, report_xml)
    findings = []
    for result in root.findall('.//results/result'):
        try:
            severity = float(result.findtext('severity', '0'))
        except ValueError:
            continue

        if severity <= 0:
            continue
        name = result.findtext('name', '')

        if 'outdated' in name.lower() and ('scan engine' in name.lower() or
                                            'scan environment' in name.lower()):
            continue
        port = result.findtext('port', '')
        nvt = result.find('nvt')
        def detail(tag):
            return (nvt.findtext(tag, '') if nvt is not None else '') or ''
        refs = []
        if nvt is not None:
            for ref in nvt.findall('.//refs/ref'):
                if ref.get('type', '').lower() == 'cve':
                    refs.append(ref.get('id', ''))
        cve = detail('cve')
        if cve and cve.lower() not in ('nocve', 'n/a'):
            refs.extend(c.strip() for c in cve.split(',') if c.strip())
        qod = result.findtext('qod/value', '')
        findings.append({
            'port': port,
            'name': name,
            'risk': 'High' if severity >= 7 else ('Medium' if severity >= 4 else 'Low'),
            'severity': severity,
            'cve': ', '.join(dict.fromkeys(refs)),
            'qod': qod,
            'description': result.findtext('description', '') or detail('summary'),
            'solution': detail('solution'),
            'insight': detail('insight'),
            'detection': detail('vuldetect'),
            'oid': nvt.get('oid', '') if nvt is not None else ''
        })
    return findings
