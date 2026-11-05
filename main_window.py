import csv
import json
import threading
import queue
import time
import tkinter as tk
from tkinter import ttk, messagebox, filedialog

import database
import scanner
import openvas

BACKGROUND = '#111215'
PANEL = '#222327'
ACCENT_RED = '#AA2938'
TEXT_WHITE = '#FFFFFF'
TEXT_GRAY = '#B8B8C0'
INPUT_BACKGROUND = '#323238'
BUTTON_HOVER = '#C83D4D'
NEUTRAL_HOVER = '#45454D'
DANGER_RED = '#8B2633'
DANGER_HOVER = '#B83344'

#Main dashboard set up
def create_window(window):
    #uses database.py to save and load scans
    database.setup_database()
    window.configure(bg=BACKGROUND)
#Connection information
    vm_ip = tk.StringVar(value='10.96.50.67')
    username = tk.StringVar(value='sp-108-green-asm')
    ssh_password = tk.StringVar()
    gvm_password = tk.StringVar()
    target_ip = tk.StringVar(value='10.96.50.59')
    search = tk.StringVar()
    status = tk.StringVar(value='Ready')
    host_status = tk.StringVar(value='Not Connected')
    displayed = {'scan': None}
    scanning = {'running': False}

    style = ttk.Style(window)
    style.theme_use('clam')
    style.configure('Accent.TButton', background=ACCENT_RED, foreground=TEXT_WHITE,
                    padding=10, font=('Arial', 11, 'bold'))
    style.configure('Neutral.TButton', background=INPUT_BACKGROUND, foreground=TEXT_WHITE,
                    padding=10, font=('Arial', 11, 'bold'))
    style.configure('Danger.TButton', background=DANGER_RED, foreground=TEXT_WHITE,
                    padding=10, font=('Arial', 11, 'bold'))
    style.map('Accent.TButton', background=[('active', BUTTON_HOVER)])
    style.map('Neutral.TButton', background=[('active', NEUTRAL_HOVER)])
    style.map('Danger.TButton', background=[('active', DANGER_HOVER)])
    style.configure('Treeview', background=PANEL, foreground=TEXT_WHITE,
                    fieldbackground=PANEL, rowheight=29)
    style.configure('Treeview.Heading', background=INPUT_BACKGROUND, foreground=TEXT_WHITE)
    style.map('Treeview', background=[('selected', ACCENT_RED)])

    def text(parent, words, size=12, bold=False):
        return tk.Label(parent, text=words, bg=parent['bg'], fg=TEXT_WHITE,
                        font=('Arial', size, 'bold' if bold else 'normal'))

    def button(parent, words, action, kind='Accent.TButton'):
        return ttk.Button(parent, text=words, command=action, style=kind)

    def field(parent, variable, hidden=False):
        return tk.Entry(parent, textvariable=variable, bg=INPUT_BACKGROUND, fg=TEXT_WHITE,
                        insertbackground=TEXT_WHITE, font=('Arial', 12), relief='flat',
                        show='*' if hidden else '')

    def table(parent, columns):
        frame = tk.Frame(parent, bg=BACKGROUND)
        frame.pack(fill='both', expand=True)
        view = ttk.Treeview(frame, columns=columns, show='headings')
        for column in columns:
            view.heading(column, text=column)
            view.column(column, width=155, minwidth=100)
        ybar = ttk.Scrollbar(frame, orient='vertical', command=view.yview)
        xbar = ttk.Scrollbar(frame, orient='horizontal', command=view.xview)
        view.configure(yscrollcommand=ybar.set, xscrollcommand=xbar.set)
        view.grid(row=0, column=0, sticky='nsew')
        ybar.grid(row=0, column=1, sticky='ns')
        xbar.grid(row=1, column=0, sticky='ew')
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)
        return view

    text(window, 'ASM Dashboard', 24, True).pack(anchor='w', padx=24, pady=(18, 12))
    nav = tk.Frame(window, bg=BACKGROUND)
    nav.pack(fill='x', padx=20)
    content = tk.Frame(window, bg=BACKGROUND)
    content.pack(fill='both', expand=True, padx=24, pady=14)
    tk.Label(window, textvariable=status, bg=BACKGROUND, fg=TEXT_GRAY).pack(
        anchor='w', padx=24, pady=9)
    tabs = {}
# the main window screen options
    def show_page(page):
        for item in content.winfo_children():
            item.destroy()
        for name, tab in tabs.items():
            tab.configure(style='Accent.TButton' if name == page else 'Neutral.TButton')
        if page == 'Dashboard':
            show_dashboard()
        elif page == 'Scan History':
            show_history()
        elif page == 'Export Results':
            show_export()
        else:
            show_settings()

    def title(words):
        text(content, words, 20, True).pack(anchor='w', pady=(2, 12))
# Show a previous scan on dashboard screen
    def display_scan(scan):
        displayed['scan'] = scan
        target_ip.set(scan['target'])
        status.set('Viewing scan #' + str(scan['id']))
        show_page('Dashboard')
#Updates dashboard after nmap finishes
    def nmap_finished(target, host, ports):
        displayed['scan'] = {
            'target': target,
            'host' : host,
            'ports': ports,
            'findings': [],
            'openvas_status': 'Running...'
        }
        show_page('Dashboard')
#Saves complete scan when finished
    def finished(target, host, ports, findings, openvas_status):
        scanning['running'] = False
        database.save_scan(target, host, ports, findings, openvas_status)
        displayed['scan'] = database.get_scans()[0]
        status.set('Finished. OpenVAS: ' + openvas_status)
        show_page('Dashboard')
        if openvas_status.startswith('Error:'):
            messagebox.showwarning('OpenVAS', openvas_status)
#Checks target monitor and starts scans
    def run_scan():
        if scanning['running']:
            messagebox.showinfo('Scan', 'A scan is already running.')
            return
        try:
            target = scanner.check_target(target_ip.get())
        except ValueError as error:
            messagebox.showerror('Target IP', str(error))
            return
        if not ssh_password.get():
            messagebox.showerror('Settings', 'Enter your SSH password in Settings.')
            return
        if not messagebox.askyesno('Confirm Scan', 'Scan authorized target ' + target + '?'):
            return
        scanning['running'] = True
        status.set('Connecting to Ubuntu...')
        vm, user, ssh_pass, gvm_pass = (vm_ip.get(), username.get(),
                                        ssh_password.get(), gvm_password.get())
#Connects to VM and runs NMAP and OpenVAS
        def perform_scan():
            connection = None
            ports = []
            findings = []
            host = 'Unknown'
            gvm_status = 'Not Started'
            try:
                connection = scanner.connect_ssh(vm, user, ssh_pass)
                if scanner.target_connected(connection, target):
                    window.after(0, lambda: host_status.set('Connected'))
                else:
                    raise RuntimeError('Target not connected. Scan cancelled.')
                window.after(0, lambda: status.set('Running Nmap...'))
                host, ports = scanner.run_nmap(connection, target, ssh_pass)
                window.after(0, lambda: nmap_finished(target, host, ports))
                if not gvm_pass:
                    gvm_status = 'Not Run (enter OpenVAS password in Settings)'
                else:
                    window.after(0, lambda: status.set('Running OpenVAS...'))
                    try:
                        task_id, report_id = openvas.start_scan(
                            connection, ssh_pass, gvm_pass, target)
                        #Checking OpenVAS progress during scan
                        for number in range(720):
                            state, progress = openvas.scan_status(
                                connection, ssh_pass, gvm_pass, task_id)
                            if state == 'Done':
                                findings = openvas.get_results(
                                    connection, ssh_pass, gvm_pass, report_id)
                                gvm_status = 'Completed'
                                break
                            if state in ('Stopped', 'Interrupted'):
                                raise RuntimeError('Scan ' + state)
                            window.after(0, lambda s=state, p=progress:
                                         status.set('OpenVAS: ' + s + ' ' + p + '%'))
                            time.sleep(15)
                        else:
                            raise RuntimeError('OpenVAS timed out')
                    except Exception as error:
                        findings = []
                        gvm_status = 'Error: ' + str(error)
            except Exception as error:
                gvm_status = 'Error: ' + str(error)

                if host == 'Unknown':
                    window.after(0, lambda e=str(error): scan_failed(e))
                    return
            finally:
                if connection:
                    connection.close()
            window.after(0, lambda: finished(target, host, ports, findings, gvm_status))
#Error for nmap
        def scan_failed(error):
            scanning['running'] = False
            status.set('Nmap failed')
            messagebox.showerror('Scan Error', error)

        threading.Thread(target=perform_scan, daemon=True).start()

    def show_dashboard():
        title('Dashboard')
        top = tk.Frame(content, bg=PANEL, padx=12, pady=12)
        top.pack(fill='x')
        text(top, 'Target IP Address').pack(side='left', padx=6)
        field(top, target_ip).pack(side='left', fill='x', expand=True, padx=12, ipady=7)
        button(top, 'Run Scan', run_scan).pack(side='right')
        scan = displayed['scan']
        ports = scan['ports'] if scan else []
        findings = scan['findings'] if scan else []
        host = scan['host'] if scan else 'Not Scanned'
#Opens security findings screen (OpenVAS results)
        def show_findings():
            popup = tk.Toplevel(window)
            popup.title('Security Findings')
            popup.geometry('1000x650')
            popup.configure(bg=BACKGROUND)
            text(popup, 'Security Findings', 18, True).pack(pady=12)
            text(popup, 'Potential vulnerabilities reported by OpenVAS', 10).pack()

            results = table(popup, ('Port', 'Severity', 'Score', 'Finding'))
            results.column('Port', width=110)
            results.column('Severity', width=110)
            results.column('Score', width=85)
            results.column('Finding', width=540)
            for index, finding in enumerate(findings):
                results.insert('', 'end', iid=str(index), values=(
                    finding.get('port', ''), finding.get('risk', ''),
                    finding.get('severity', ''), finding.get('name', '')))


            details = tk.Text(popup, bg=INPUT_BACKGROUND, fg=TEXT_WHITE,
                              wrap='word', height=12, font=('Arial', 11))
            details.pack(fill='both', expand=True, padx=12, pady=8)
            details.configure(state='disabled')
#Shows details when click on a security finding (still in progress)
            def show_details(event=None):
                selected = results.selection()
                if not selected:
                    return
                finding = findings[int(selected[0])]
                parts = [
                    'Finding: ' + finding.get('name', ''),
                    'Port: ' + finding.get('port', ''),
                    'Risk: ' + finding.get('risk', ''),
                    'Severity score: ' + str(finding.get('severity', '')),
                    'CVE: ' + (finding.get('cve') or 'Not provided'),
                    'Detection confidence (QoD): ' + str(finding.get('qod') or 'Not provided'),
                    '', 'Description:', finding.get('description') or 'Not provided',
                    '', 'Evidence / Detection:',
                    finding.get('detection') or finding.get('insight') or 'Not provided',
                    '', 'Recommended Solution:', finding.get('solution') or 'Not provided'
                ]
                details.configure(state='normal')
                details.delete('1.0', 'end')
                details.insert('1.0', '\n'.join(parts))
                details.configure(state='disabled')
            results.bind('<<TreeviewSelect>>', show_details)
            button(popup, 'Close X', popup.destroy).pack(pady=9)
        cards = tk.Frame(content, bg=BACKGROUND)
        cards.pack(fill='x', pady=15)
        values = [('Host Status', host_status.get()), ('Open Ports', str(sum(p.get('state') == 'open' for p in ports))),
                  ('Services', str(len({p['service'] for p in ports}))),
                  ('Security Findings', str(len(findings)) if
                   scan and scan['openvas_status'] == 'Completed' else 'Not Verified')]
        for heading, value in values:
            card = tk.Frame(cards, bg=PANEL, padx=8, pady=14)
            card.pack(side='left', fill='both', expand=True, padx=4)

            name_label = text(card, heading, 10)
            name_label.pack()

            if heading == 'Host Status':
                tk.Label(card, textvariable=host_status, bg=PANEL,
                         fg=TEXT_WHITE, font=('Arial', 16, 'bold')).pack(pady=7)
            else:
                count_label = text(card, value, 16, True)
                count_label.pack(pady=7)

                if heading == 'Security Findings' and scan and scan['openvas_status'] == 'Completed':
                    for item in (card, name_label, count_label):
                        item.bind('<Button-1>', lambda event: show_findings())
        if scan:
            text(content, 'OpenVAS Status: ' + scan['openvas_status'], 10).pack(anchor='w')
        search_row = tk.Frame(content, bg=BACKGROUND)
        search_row.pack(fill='x', pady=8)
        text(search_row, 'Scan Results', 16, True).pack(side='left')
        search_box = field(search_row, search)
        search_box.pack(side='right', ipady=6)
        text(search_row, 'Search ports/services:').pack(side='right', padx=8)
        view = table(content, ('Port', 'Service', 'Application', 'Version', 'State', 'Risk'))
        for column, width in [('Port', 90), ('Service', 140),
                              ('Application', 230), ('Version', 250),
                              ('State', 90), ('Risk', 110)]:
            view.column(column, width=width, minwidth=80, stretch=True)
# Updates Risk levels
        def update_rows(event=None):
            for item in view.get_children():
                view.delete(item)
            term = search.get().lower()
            for port in ports:
                number = str(port['port'])
                service = port['service']
                if term not in (number + ' ' + service).lower():
                    continue

                matches = [f for f in findings if f.get('port', '').lower() == number.lower()]
                highest = max((float(f.get('severity', 0)) for f in matches), default=0)
                risk = ('🔴 High' if highest >= 7 else
                        '🟠 Medium' if highest >= 4 else
                        '🟢 Low' if highest > 0 else 'Not Assessed')
                view.insert('', 'end', values=(number, service,
                                               port.get('application', 'Unknown'),
                                               port['version'], port['state'], risk))
        search_box.bind('<KeyRelease>', update_rows)
        update_rows()
        bottom = tk.Frame(content, bg=BACKGROUND)
        bottom.pack(fill='x', pady=12)
        text(bottom, 'Previous Scan:').pack(side='left')
        scans = database.get_scans()
        labels = [str(s['id']) + ' - ' + s['date'] + ' - ' + s['target'] for s in scans]
        previous = ttk.Combobox(bottom, values=labels, state='readonly', width=40)
        previous.pack(side='left', padx=12)
# Shows a previous scan on the dashboard screen
        def choose_previous(event):
            scan_id = int(previous.get().split(' - ')[0])
            for old in scans:
                if old['id'] == scan_id:
                    display_scan(old)
                    break
        previous.bind('<<ComboboxSelected>>', choose_previous)
# Clears the results on dashboard
        def clear_results():
            displayed['scan'] = None
            search.set('')
            status.set('Results cleared (history is saved)')
            show_page('Dashboard')
        button(bottom, 'Clear Results', clear_results, 'Danger.TButton').pack(side='right')
# Scan history tab shows all saved scans
    def show_history():
        title('Scan History')
        scans = database.get_scans()
        view = table(content, ('ID', 'Date', 'Target', 'Open Ports', 'Vulnerabilities', 'OpenVAS'))
        for scan in scans:
            view.insert('', 'end', values=(scan['id'], scan['date'], scan['target'],
                         len(scan['ports']), len(scan['findings']), scan['openvas_status']))

        def open_selected():
            chosen = view.selection()
            if not chosen:
                messagebox.showinfo('History', 'Select a scan first.')
                return
            scan_id = int(view.item(chosen[0], 'values')[0])
            for old in scans:
                if old['id'] == scan_id:
                    display_scan(old)
                    return
        button(content, 'Display Selected Scan', open_selected).pack(anchor='e', pady=12)
# Export results tab
    def show_export():
        title('Export Results')
        scans = database.get_scans()
        selected = {}
        options = tk.Frame(content, bg=PANEL, padx=16, pady=12)
        options.pack(fill='both', expand=True)
        text(options, 'Select one, some, or all scans', 15, True).pack(anchor='w', pady=8)
        checks = tk.Frame(options, bg=PANEL)
        checks.pack(fill='both', expand=True)
        for scan in scans:
            checked = tk.BooleanVar(value=False)
            selected[scan['id']] = checked
            tk.Checkbutton(checks, text=scan['date'] + '  |  ' + scan['target'],
                           variable=checked, bg=PANEL, fg=TEXT_WHITE,
                           selectcolor=INPUT_BACKGROUND, activebackground=PANEL,
                           activeforeground=TEXT_WHITE).pack(anchor='w', pady=3)

        def select_all():
            for checked in selected.values():
                checked.set(True)
        button(options, 'Select All', select_all).pack(anchor='w', pady=6)
        bottom = tk.Frame(content, bg=BACKGROUND)
        bottom.pack(fill='x', pady=12)
        text(bottom, 'Format:').pack(side='left')
        file_format = tk.StringVar(value='CSV')
        ttk.Combobox(bottom, textvariable=file_format, state='readonly',
                     values=['CSV', 'JSON'], width=9).pack(side='left', padx=9)

        def export():
            chosen = [s for s in scans if selected[s['id']].get()]
            if not chosen:
                messagebox.showerror('Export', 'Select at least one scan.')
                return
            extension = file_format.get().lower()
            path = filedialog.asksaveasfilename(defaultextension='.' + extension,
                                                filetypes=[(extension.upper(), '*.' + extension)])
            if not path:
                return
            if extension == 'json':
                with open(path, 'w', encoding='utf-8') as file:
                    json.dump(chosen, file, indent=2)
            else:
                with open(path, 'w', newline='', encoding='utf-8') as file:
                    writer = csv.writer(file)
                    writer.writerow(['Scan ID', 'Date', 'Target', 'Type', 'Port',
                                     'Service', 'Application', 'Version', 'Risk', 'Finding', 'Status'])
                    for scan in chosen:
                        for port in scan['ports']:
                            writer.writerow([scan['id'], scan['date'], scan['target'],
                                             'Nmap', port['port'], port['service'],
                                             port.get('application', 'Unknown'), port['version'],
                                             '', '', scan['openvas_status']])
                        for finding in scan['findings']:
                            writer.writerow([scan['id'], scan['date'], scan['target'],
                                             'OpenVAS', finding['port'], '', '', '',
                                             finding['risk'], finding['name'], scan['openvas_status']])
                        if not scan['ports'] and not scan['findings']:
                            writer.writerow([scan['id'], scan['date'], scan['target'],
                                             '', '', '', '', '', '', '', scan['openvas_status']])
            messagebox.showinfo('Export', 'File saved successfully.')
        button(bottom, 'Export Selected Scans', export).pack(side='right')
# Settings tab
    def show_settings():
        title('Settings')
        panel = tk.Frame(content, bg=PANEL, padx=18, pady=12)
        panel.pack(fill='x', pady=8)
        text(panel, 'Connection Settings', 16, True).pack(anchor='w', pady=8)
        for words, variable, secret in [('Ubuntu VM IP', vm_ip, False),
                                        ('SSH Username', username, False),
                                        ('SSH Password', ssh_password, True),
                                        ('OpenVAS Admin Password', gvm_password, True)]:
            row = tk.Frame(panel, bg=PANEL)
            row.pack(fill='x', pady=5)
            text(row, words).pack(side='left')
            field(row, variable, secret).pack(side='right', fill='x', expand=True,
                                             padx=(15, 0), ipady=5)
        text(panel, 'Passwords stay in memory only while the app is open.', 10).pack(
            anchor='w', pady=6)
        result = tk.StringVar(value='')
        messages = queue.Queue()
# Test the SSH and OpenVAS connection
        def test_connection():
            vm = vm_ip.get()
            user = username.get()
            ssh_pass = ssh_password.get()
            gvm_pass = gvm_password.get()

            result.set('Checking Connection...')

            def check():
                connection = None

                try:
                    connection = scanner.connect_ssh(vm, user, ssh_pass)

                    openvas.gvm_command(
                        connection, ssh_pass, gvm_pass, '<get_version/>'
                    )

                    messages.put('Both Connections Successful')

                except Exception:
                    messages.put('Connection Unsuccessful. Please Try Again.')

                finally:
                    if connection:
                        connection.close()

            def show_result():
                if messages.empty():
                    window.after(100, show_result)
                else:
                    result.set(messages.get())

            threading.Thread(target=check, daemon=True).start()
            show_result()

        button(panel, 'Test Connection', test_connection).pack(anchor='e', pady=8)

        tk.Label(panel, textvariable=result, bg=PANEL,
                 fg=TEXT_WHITE).pack(anchor='e')
        delete_panel = tk.Frame(content, bg=PANEL, padx=18, pady=12)
        delete_panel.pack(fill='x', pady=12)
        text(delete_panel, 'Delete Saved Scans', 16, True).pack(anchor='w', pady=8)
        scans = database.get_scans()
        labels = [str(s['id']) + ' - ' + s['date'] + ' - ' + s['target'] for s in scans]
        choice = ttk.Combobox(delete_panel, values=labels, state='readonly', width=48)
        choice.pack(anchor='w', pady=8)
# Delete a saved scan
        def delete_selected():
            if not choice.get():
                messagebox.showinfo('Delete', 'Select a scan first.')
                return
            if messagebox.askyesno('Confirm Delete', 'Permanently delete this saved scan?'):
                database.delete_scan(int(choice.get().split(' - ')[0]))
                displayed['scan'] = None
                show_page('Settings')
        button(delete_panel, 'Delete Selected Scan', delete_selected,
               'Danger.TButton').pack(anchor='e', pady=8)

    for name in ['Dashboard', 'Scan History', 'Export Results', 'Settings']:
        tabs[name] = button(nav, name, lambda page=name: show_page(page), 'Neutral.TButton')
        tabs[name].pack(side='left', padx=5)
    show_page('Dashboard')

