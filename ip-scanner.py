#!/usr/bin/env python3
from __future__ import annotations
import os
import re
import sys
import time
import socket
import ipaddress
import threading
import queue
import csv
import argparse
from datetime import datetime
from dataclasses import dataclass, field

import paramiko
from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt
from rich.panel import Panel
from rich.text import Text
from rich.align import Align
from rich import box
from rich.rule import Rule
from rich.live import Live

console = Console()
STOP_EVENT = threading.Event()


@dataclass
class IpScanDetail:
    ip: str
    configured: bool = False
    config_interface: str = ""
    route_known: bool = False
    route_protocol: str = ""
    route_nexthop: str = ""
    route_interface: str = ""
    is_static: bool = False
    arp_known: bool = False
    arp_mac: str = ""
    arp_interface: str = ""


@dataclass
class DeviceResult:
    host: str
    hostname: str = ""
    detalhes: list[IpScanDetail] = field(default_factory=list)
    erro: str = ""
    sucesso: bool = False


def _parse_interfaces(intf_output: str) -> tuple[dict[str, str], list[tuple[ipaddress.IPv4Network, str]]]:
    configured_ips = {} # ip -> interface
    configured_subnets = [] # (network, interface)
    
    for line in intf_output.split("\n"):
        line_clean = line.strip()
        if not line_clean or "interface" in line_clean.lower() or "ip-address" in line_clean.lower():
            continue
        tokens = line_clean.split()
        if len(tokens) >= 2:
            iface = tokens[0]
            for tok in tokens[1:]:
                if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", tok):
                    ip_addr = tok
                    if ip_addr != "0.0.0.0" and ip_addr != "unassigned" and ip_addr != "NO_IP":
                        configured_ips[ip_addr] = iface
                        try:
                            configured_subnets.append((ipaddress.ip_network(f"{ip_addr}/24", strict=False), iface))
                        except Exception:
                            pass
                    break
    return configured_ips, configured_subnets


def _parse_routes(route_output: str) -> list[dict]:
    routes = []
    current_net = None
    current_protocol = ""
    current_is_static = False
    
    lines = route_output.split("\n")
    for line in lines:
        line_clean = line.strip()
        line_lower = line_clean.lower()
        if not line_clean or "ip route table for vrf" in line_lower or "denotes" in line_lower or "preference" in line_lower or "%" in line_lower:
            continue
            
        m_net = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3}/\d{1,2})\b", line_clean)
        
        line_proto = ""
        is_st = False
        if "static" in line_lower or "ip route" in line_lower:
            is_st = True
            line_proto = "static"
        elif "ospf" in line_lower or "type-1" in line_lower or "type-2" in line_lower:
            line_proto = "ospf"
        elif "bgp" in line_lower:
            line_proto = "bgp"
        elif "attached" in line_lower or "connected" in line_lower:
            line_proto = "connected"

        if re.match(r"^[A-Z\*]+\s+\d{1,3}", line_clean):
            if line_clean.startswith("C") or "connected" in line_lower:
                line_proto = "connected"
            elif line_clean.startswith("S") or "static" in line_lower or "ip route" in line_lower:
                is_st = True
                line_proto = "static"
            elif line_clean.startswith("O") or "ospf" in line_lower:
                line_proto = "ospf"
            elif line_clean.startswith("B") or "bgp" in line_lower:
                line_proto = "bgp"

        if m_net:
            try:
                net_str = m_net.group(1)
                current_net = ipaddress.ip_network(net_str, strict=False)
                current_protocol = line_proto
                current_is_static = is_st
            except Exception:
                pass
        elif current_net and (("via" in line_lower) or ("connected" in line_lower) or ("*via" in line_lower)):
            if not current_protocol and line_proto:
                current_protocol = line_proto
            if is_st:
                current_is_static = True
                current_protocol = "static"

        if current_net:
            nexthop = ""
            if "directly connected" in line_lower:
                nexthop = "directly connected"
                if not current_protocol:
                    current_protocol = "connected"
            elif "via" in line_lower:
                parts = line_lower.split("via")
                if len(parts) > 1:
                    tokens = [t.strip(",[]") for t in parts[1].split() if t.strip(",[]")]
                    if tokens:
                        nh_cand = tokens[0]
                        if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", nh_cand):
                            nexthop = nh_cand

            iface = ""
            tokens = [t.strip(",[]") for t in line_clean.split() if t.strip(",[]")]
            for tok in tokens:
                tok_l = tok.lower()
                if any(k in tok_l for k in ["vlan", "eth", "gi", "te", "po", "lo", "mgmt", "fa"]) and not "ospf" in tok_l and not "type" in tok_l and not "/" in tok_l and len(tok) < 15:
                    iface = tok.rstrip(",")
                    break
                if re.match(r"^(vlan|gi|eth|te|fa|po|lo)\d+.*", tok_l):
                    iface = tok.rstrip(",")
                    break

            if nexthop or iface or "connected" in line_lower or current_protocol:
                proto_final = current_protocol
                if current_is_static:
                    proto_final = "static"
                elif not proto_final or proto_final == "connected":
                    if any(k in route_output.lower() for k in ["ospf", "type-1", "type-2"]) and "ospf" not in proto_final:
                        # Se o output geral tiver indicação OSPF mas a rota veio vazia/connected
                        pass

                routes.append({
                    "network": current_net,
                    "protocol": proto_final if proto_final else "connected",
                    "nexthop": nexthop or ("directly connected" if proto_final == "connected" else ""),
                    "interface": iface,
                    "is_static": current_is_static
                })
    return routes


def _parse_arp(arp_output: str) -> dict[str, dict[str, str]]:
    arp_data = {}
    for line in arp_output.split("\n"):
        line_clean = line.strip()
        if not line_clean or "protocol" in line_clean.lower() or "flags" in line_clean.lower() or "address" in line_clean.lower():
            continue
        m_ip = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", line_clean)
        if not m_ip:
            continue
        arp_ip = m_ip.group(1)
        
        m_mac = re.search(r"\b([a-fA-F0-9]{4}\.[a-fA-F0-9]{4}\.[a-fA-F0-9]{4}|[a-fA-F0-9]{2}(?::[a-fA-F0-9]{2}){5}|[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4})\b", line_clean)
        mac = m_mac.group(1) if m_mac else ""
        
        tokens = line_clean.split()
        ifif = ""
        for tok in tokens:
            tok_l = tok.lower()
            if any(k in tok_l for k in ["vlan", "eth", "gi", "te", "po", "lo", "mgmt", "fa"]) and not tok_l == arp_ip.lower():
                ifif = tok.rstrip(",")
                break
                
        if arp_ip:
            arp_data[arp_ip] = {"mac": mac, "interface": ifif}
            
    return arp_data


def _parse_device_data(intf_out: str, route_out: str, arp_out: str, ips: list[str]) -> list[IpScanDetail]:
    detalhes = []
    
    configured_ips, configured_subnets = _parse_interfaces(intf_out)
    routes = _parse_routes(route_out)
    arp_data = _parse_arp(arp_out)
    
    for ip in ips:
        configured = False
        config_if = ""
        if ip in configured_ips:
            configured = True
            config_if = configured_ips[ip]
        else:
            try:
                ip_obj = ipaddress.ip_address(ip)
                for net, iface in configured_subnets:
                    if ip_obj in net:
                        configured = True
                        config_if = iface
                        break
            except Exception:
                pass

        r_info = {
            "known": False,
            "protocol": "",
            "nexthop": "",
            "interface": "",
            "is_static": False
        }
        
        try:
            target_ip = ipaddress.ip_address(ip)
            best_match = None
            max_prefix_len = -1
            
            for r in routes:
                if target_ip in r['network']:
                    prefix_len = r['network'].prefixlen
                    if prefix_len > max_prefix_len:
                        max_prefix_len = prefix_len
                        best_match = r
                        
            if best_match:
                r_info = {
                    "known": True,
                    "protocol": best_match['protocol'],
                    "nexthop": best_match['nexthop'],
                    "interface": best_match['interface'],
                    "is_static": best_match['is_static']
                }
        except Exception:
            pass

        arp_info = arp_data.get(ip, {"mac": "", "interface": ""})

        det = IpScanDetail(
            ip=ip,
            configured=configured,
            config_interface=config_if,
            route_known=r_info["known"],
            route_protocol=r_info["protocol"],
            route_nexthop=r_info["nexthop"],
            route_interface=r_info["interface"] or config_if,
            is_static=r_info["is_static"],
            arp_known=bool(arp_info["mac"]),
            arp_mac=arp_info["mac"],
            arp_interface=arp_info["interface"]
        )
        detalhes.append(det)

    return detalhes


def _scan_device(host: str, user: str, password: str,
                 ips: list[str], result_queue: queue.Queue):
    res = DeviceResult(host=host)
    client = None
    try:
        paramiko.Transport._preferred_keys = (
            'ecdsa-sha2-nistp256', 'ecdsa-sha2-nistp384', 'ecdsa-sha2-nistp521',
            'ssh-ed25519', 'rsa-sha2-512', 'rsa-sha2-256', 'ssh-rsa',
        )
        paramiko.Transport._preferred_kex = (
            'ecdh-sha2-nistp256', 'ecdh-sha2-nistp384', 'ecdh-sha2-nistp521',
            'diffie-hellman-group-exchange-sha256',
            'diffie-hellman-group14-sha256', 'diffie-hellman-group14-sha1',
            'diffie-hellman-group1-sha1',
        )
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(host, username=user, password=password,
                       timeout=10, look_for_keys=False, allow_agent=False,
                       banner_timeout=15, auth_timeout=15,
                       disabled_algorithms={'pubkeys': ['rsa-sha2-256', 'rsa-sha2-512']})
        channel = client.invoke_shell(width=512, height=50000)
        time.sleep(1)
        try:
            channel.recv(99999)
        except Exception:
            pass
        channel.send("terminal length 0\n")
        time.sleep(0.3)
        channel.send("terminal no monitor\n")
        time.sleep(0.3)
        channel.send("no logging console\n")
        time.sleep(0.3)

        def run_cmd(cmd: str, timeout: int = 15) -> str:
            if STOP_EVENT.is_set():
                return ""
            channel.send(cmd + "\n")
            output = b""
            end_time = time.time() + timeout
            while time.time() < end_time:
                try:
                    if channel.recv_ready():
                        data = channel.recv(65535)
                        if data:
                            output += data
                            if re.search(rb'[>#]\s*$', data):
                                break
                    else:
                        if output and time.time() > end_time - 3:
                            break
                        time.sleep(0.2)
                except socket.timeout:
                    break
            return output.decode("utf-8", errors="replace")

        intf_out = run_cmd("show ip interface brief", timeout=15)
        arp_out = run_cmd("show ip arp", timeout=15)
        route_out = run_cmd("show ip route", timeout=30)

        res.detalhes = _parse_device_data(intf_out, route_out, arp_out, ips)
        res.sucesso = True
        channel.close()
    except paramiko.AuthenticationException:
        res.erro = "Auth falhou"
    except paramiko.SSHException as e:
        res.erro = f"SSH: {str(e)[:60]}"
    except socket.timeout:
        res.erro = "Timeout"
    except socket.gaierror:
        res.erro = "Hostname invalido"
    except EOFError:
        res.erro = "Conexao fechada"
    except Exception as e:
        erro_str = str(e)[:80]
        if "Error reading SSH protocol banner" in erro_str:
            res.erro = "Banner SSH invalido"
        elif "Channel closed" in erro_str:
            res.erro = "Channel closed"
        else:
            res.erro = erro_str
    finally:
        if client:
            try:
                client.close()
            except Exception:
                pass

    result_queue.put(res)
    STOP_EVENT.wait(0.01)


def show_banner():
    console.clear()
    console.print(r"""
[bold cyan]
::::::::::: :::::::::                                                           
    :+:     :+:    :+:                                                          
    +:+     +:+    +:+                                                          
    +#+     +#++:++#+                                                           
    +#+     +#+                                                                 
    #+#     #+#                                                                 
########### ###                                                                 
 ::::::::   ::::::::      :::     ::::    ::: ::::    ::: :::::::::: :::::::::  
:+:    :+: :+:    :+:   :+: :+:   :+:+:   :+: :+:+:   :+: :+:        :+:    :+: 
+:+        +:+         +:+   +:+  :+:+:+  +:+ :+:+:+  +:+ +:+        +:+    +:+ 
+#++:++#++ +#+        +#++:++#++: +#+ +:+ +#+ +#+ +:+ +#+ +#++:++#   +#++:++#:  
       +#+ +#+        +#+     +#+ +#+  +#+#+# +#+  +#+#+# +#+        +#+    +#+ 
#+#    #+# #+#    #+# #+#     #+# #+#   #+#+# #+#   #+#+# #+#        #+#    #+# 
 ########   ########  ###     ### ###    #### ###    #### ########## ###    ### 
 .::::::::::::::::.
                                   .::##################::.
                                 .::######################::.
                                .::######::::::::::::::######::.
                               .::######::            ::######::.
                               ::######::              ::######::
                               ::######::              ::######::
                               ::######::              ::######::
                               .::######::            ::######::.
                                .::######::::::::::::::######::.
                                 .::######################::.
                                   .::##################::.  ::.
                                      .::::::::::::::::.      ::.
                                                                ::.
                                                                  ::.
                                                                    ::.
                                                                      ::.

            AUTOR - VINICIUS CLEMENTE
[bold yellow]          IP SCANNER & NETWORK AUTOMATION TOOL
[bold white]-----------------------------------------------------------------------------
 Valida configuracao, rotas, rotas estaticas e entradas ARP em switches L3 e Roteadores
 Equipamentos: CISCO NXOS / CATALYST / BROCADE / INFINERA
 Autor - VINICIUS CLEMENTE
-----------------------------------------------------------------------------
[/bold white]
""")


def carregar_hosts(caminho: str) -> list[str]:
    hosts = []
    with open(caminho, encoding="utf-8") as f:
        for linha in f:
            linha = linha.strip()
            if linha and not linha.startswith("#"):
                hosts.append(linha)
    return hosts


def exportar_csv_simples(resultados: list[DeviceResult], caminho: str):
    with open(caminho, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["host", "ip", "configurado", "config_interface", "rota_conhecida", "protocolo", "rota_estatica", "next_hop", "rota_interface", "arp_conhecido", "arp_mac", "arp_interface"])
        for r in resultados:
            if not r.sucesso:
                w.writerow([r.host, "ERRO", r.erro, "", "", "", "", "", "", "", "", ""])
                continue
            for d in r.detalhes:
                w.writerow([
                    r.host, d.ip,
                    "sim" if d.configured else "nao", d.config_interface,
                    "sim" if d.route_known else "nao", d.route_protocol,
                    "sim" if d.is_static else "nao", d.route_nexthop, d.route_interface,
                    "sim" if d.arp_known else "nao", d.arp_mac, d.arp_interface
                ])
    console.print(f"\n[green]CSV salvo: {caminho}[/green]")


def exportar_csv_agrupado(resultados: list[DeviceResult], caminho: str):
    ips = set()
    for r in resultados:
        if r.sucesso:
            for d in r.detalhes:
                ips.add(d.ip)

    with open(caminho, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        devices = [r for r in resultados if r.sucesso]
        header = ["ip"]
        for d in devices:
            header.extend([f"{d.host}_config", f"{d.host}_rota", f"{d.host}_protocolo", f"{d.host}_estatica", f"{d.host}_next_hop", f"{d.host}_arp_mac"])
        w.writerow(header)

        for ip in sorted(ips):
            row = [ip]
            for d in devices:
                det = next((x for x in d.detalhes if x.ip == ip), None)
                if det:
                    row.extend([
                        "sim" if det.configured else "nao",
                        "sim" if det.route_known else "nao",
                        det.route_protocol,
                        "sim" if det.is_static else "nao",
                        det.route_nexthop,
                        det.arp_mac
                    ])
                else:
                    row.extend(["nao", "nao", "", "nao", "", ""])
            w.writerow(row)

    console.print(f"\n[green]CSV agrupado salvo: {caminho}[/green]")


def _tabela_geral_scan(resultados: list[DeviceResult], total_hosts: int, processados: int) -> Table:
    t = Table(box=box.SQUARE, border_style="cyan",
              title=f"[bold]SCAN IP L3 & ROUTE - {processados}/{total_hosts} hosts[/bold]")
    t.add_column("Host", width=25, no_wrap=True)
    t.add_column("Status", width=8)
    t.add_column("Config", justify="right", width=8)
    t.add_column("Rotas", justify="right", width=8)
    t.add_column("Estaticas", justify="right", width=10)
    t.add_column("ARP", justify="right", width=8)
    t.add_column("Erro", width=30)
    for r in resultados:
        if r.erro:
            t.add_row(r.host, "[red]ERRO[/red]", "0", "0", "0", "0", r.erro[:28])
        else:
            configados = sum(1 for d in r.detalhes if d.configured)
            conhecidos = sum(1 for d in r.detalhes if d.route_known)
            estaticas = sum(1 for d in r.detalhes if d.is_static)
            arps = sum(1 for d in r.detalhes if d.arp_known)
            total = len(r.detalhes)
            t.add_row(
                r.host, "[green]OK[/green]",
                f"[cyan]{configados}[/cyan]/[dim]{total}[/dim]",
                f"[cyan]{conhecidos}[/cyan]/[dim]{total}[/dim]",
                f"[yellow]{estaticas}[/yellow]",
                f"[magenta]{arps}[/magenta]",
                ""
            )
    return t


def _executar_scan(hosts: list[str], user: str, password: str,
                   ips: list[str], max_threads: int) -> list[DeviceResult]:
    STOP_EVENT.clear()
    resultados: list[DeviceResult] = []
    resultados_lock = threading.Lock()
    q: queue.Queue = queue.Queue()

    def consumir():
        while not STOP_EVENT.is_set() or not q.empty():
            try:
                item = q.get(timeout=0.2)
                with resultados_lock:
                    resultados.append(item)
            except queue.Empty:
                pass

    consumer = threading.Thread(target=consumir, daemon=True)
    consumer.start()

    console.print(f"\n[bold cyan]Escaneando {len(ips)} IPs em {len(hosts)} hosts (Config, Rotas, Estáticas, ARP)...[/bold cyan]")
    console.print(f"[dim]Threads: {max_threads}[/dim]\n")

    with Live(refresh_per_second=2, console=console) as live:
        for i in range(0, len(hosts), max_threads):
            if STOP_EVENT.is_set():
                break
            batch = hosts[i:i + max_threads]
            threads = []
            for h in batch:
                t = threading.Thread(target=_scan_device,
                                     args=(h, user, password, ips, q), daemon=True)
                t.start()
                threads.append(t)
            for t in threads:
                t.join(timeout=120)
                if t.is_alive():
                    STOP_EVENT.set()
            with resultados_lock:
                current = len(resultados)
            live.update(_tabela_geral_scan(resultados, len(hosts),
                                           min(i + max_threads, len(hosts))))

    STOP_EVENT.set()
    time.sleep(0.5)
    consumer.join(timeout=2)
    return resultados


def _exibir_resultados(resultados: list[DeviceResult], hosts: list[str], ips: list[str]):
    sucessos = [r for r in resultados if r.sucesso]
    erros = [r for r in resultados if not r.sucesso]

    console.print()
    t = Table(box=box.SQUARE, border_style="green")
    t.add_column("Metrica", style="bold cyan", width=25)
    t.add_column("Valor")
    t.add_row("Total hosts", str(len(hosts)))
    t.add_row("Sucesso", f"[green]{len(sucessos)}[/green]")
    t.add_row("Erro", f"[red]{len(erros)}[/red]")
    t.add_row("IPs verificados", str(len(ips)))
    console.print(t)

    if erros:
        console.print(f"\n[red]Falhas:[/red]")
        for r in erros:
            console.print(f"  {r.host} - {r.erro}")

    console.print()
    console.print(_tabela_geral_scan(resultados, len(hosts), len(hosts)))

    if sucessos:
        console.print()
        t3 = Table(box=box.SQUARE, border_style="cyan",
                   title="[bold]DETALHAMENTO POR DISPOSITIVO E IP[/bold]")
        t3.add_column("Host", width=25, no_wrap=True)
        t3.add_column("IP", width=15)
        t3.add_column("Config?", width=10)
        t3.add_column("Rota?", width=8)
        t3.add_column("Protocolo", width=10)
        t3.add_column("Estatica?", width=10)
        t3.add_column("Next Hop", width=15)
        t3.add_column("Interface", width=12)
        t3.add_column("ARP?", width=6)
        t3.add_column("MAC ARP", width=17)

        for d in sucessos:
            for det in d.detalhes:
                cfg_str = f"[green]Sim[/green]({det.config_interface})" if det.configured else "[dim]Nao[/dim]"
                route_str = "[green]Sim[/green]" if det.route_known else "[red]Nao[/red]"
                static_str = "[yellow]Sim[/yellow]" if det.is_static else "[dim]Nao[/dim]"
                arp_str = "[magenta]Sim[/magenta]" if det.arp_known else "[dim]Nao[/dim]"
                
                t3.add_row(
                    f"[bold]{d.host}[/bold]",
                    f"[cyan]{det.ip}[/cyan]",
                    cfg_str,
                    route_str,
                    det.route_protocol or "-",
                    static_str,
                    det.route_nexthop or "-",
                    det.route_interface or det.arp_interface or "-",
                    arp_str,
                    det.arp_mac or "-"
                )
        console.print(t3)


def cabecalho(titulo: str):
    console.clear()
    console.print(Rule(style="cyan"))
    console.print(Align.center(Text(titulo, style="bold cyan", no_wrap=True)))
    console.print(Rule(style="cyan"))


def pausa():
    Prompt.ask("\n[dim]Pressione Enter para continuar[/dim]", default="")


def _config_scan():
    cabecalho("CONFIGURACAO DO SCAN IP & ROUTE & ARP")
    console.print(Panel(
        "[yellow]Arquivo de hosts L3[/yellow]: IPs/hostnames dos equipamentos L3, um por linha\n"
        "[yellow]Verificacoes[/yellow]: Configuração local, Rotas (incluindo estáticas), Entradas ARP e VLANs\n"
        "[yellow]Acesso[/yellow]: SSH (mesmo usuario/senha para todos)",
        border_style="cyan", title="SSH & Redes"
    ))

    default_hosts_file = "l3-hosts.txt"
    arquivo = Prompt.ask("[bold cyan]Arquivo com hosts L3[/bold cyan]", default=default_hosts_file)
    if not os.path.isfile(arquivo):
        console.print(f"[yellow]Arquivo {arquivo} nao existe. Criando modelo.[/yellow]")
        with open(arquivo, "w", encoding="utf-8") as f:
            f.write("# Lista de IPs/hostnames dos equipamentos L3 (um por linha)\n")
            f.write("# Exemplo:\n")
            f.write("# 10.0.0.1\n")
            f.write("# SPB-VIV-CORE-RT01\n")
        console.print(f"[green]Arquivo {arquivo} criado. Edite e execute novamente.[/green]")
        pausa()
        return None

    hosts = carregar_hosts(arquivo)
    if not hosts:
        console.print("[red]Nenhum host no arquivo[/red]")
        pausa()
        return None
    console.print(f"[cyan]Total: {len(hosts)} hosts L3[/cyan]")

    user = Prompt.ask("[bold cyan]Usuario SSH[/bold cyan]")
    password = Prompt.ask("[bold cyan]Senha SSH[/bold cyan]", password=True)
    max_threads = int(Prompt.ask("[bold cyan]Threads[/bold cyan]", default="10"))

    console.print()
    console.print(Panel("[yellow]Range de IPs para verificar[/yellow]",
                        border_style="cyan", title="IPs"))
    entrada = Prompt.ask("[bold cyan]Rede[/bold cyan] (ex: 179.131.24.0/29 ou 10.0.0.1-10.0.0.20)")
    ips = parse_ips(entrada)

    if not ips:
        console.print("[red]Nenhum IP valido[/red]")
        pausa()
        return None

    console.print(f"[cyan]Total IPs para verificar: {len(ips)}[/cyan]")
    if len(ips) > 50:
        console.print("[yellow]ATENCAO: Muitos IPs podem tornar o scan lento![/yellow]")

    return hosts, user, password, max_threads, ips


def validar_range():
    cfg = _config_scan()
    if not cfg:
        return
    hosts, user, password, max_threads, ips = cfg

    resultados = _executar_scan(hosts, user, password, ips, max_threads)
    _exibir_resultados(resultados, hosts, ips)

    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    exportar_csv_simples(resultados, f"ip-scanner-detalhado-{ts}.csv")
    exportar_csv_agrupado(resultados, f"ip-scanner-agrupado-{ts}.csv")
    pausa()


def menu_principal():
    while True:
        console.clear()
        show_banner()

        menu = Table(box=box.SIMPLE_HEAVY, border_style="bright_blue", show_header=False)
        menu.add_column("opt", style="bold yellow", width=4)
        menu.add_column("desc", style="white")
        menu.add_row("[1]", "Verificar range (Config, Rotas, Estáticas, ARP)")
        menu.add_row("", "")
        menu.add_row("[0]", "Sair")

        console.print(Align.center(menu))

        op = Prompt.ask("[bold cyan]Escolha uma opcao",
                        choices=["0", "1"])

        if op == "0":
            cabecalho("ATE LOGO!")
            console.print("[green]Saindo...[/green]")
            break
        elif op == "1":
            validar_range()


def parse_ips(entrada: str) -> list[str]:
    ips = []
    if "/" in entrada:
        rede = ipaddress.ip_network(entrada, strict=False)
        ips = [str(ip) for ip in rede.hosts()]
    elif "-" in entrada:
        partes = entrada.split("-")
        inicio = ipaddress.ip_address(partes[0].strip())
        fim = ipaddress.ip_address(partes[1].strip())
        ip_int_inicio = int(inicio)
        ip_int_fim = int(fim)
        ips = [str(ipaddress.ip_address(i)) for i in range(ip_int_inicio, ip_int_fim + 1)]
    elif "," in entrada:
        for p in entrada.split(","):
            p = p.strip()
            if p:
                ips.append(p)
    else:
        ips = [entrada.strip()]
    return ips


def main():
    parser = argparse.ArgumentParser(description="Scanner IP L3 & Route & ARP")
    parser.add_argument("hosts_file", nargs="?", help="Arquivo com hosts L3 (um por linha)")
    parser.add_argument("--threads", type=int, default=10, help="Threads (default: 10)")
    parser.add_argument("--rede", help="Rede CIDR (ex: 179.131.24.0/29)")
    parser.add_argument("--range", help="Range (ex: 10.0.0.1-10.0.0.20)")
    parser.add_argument("--ips", help="Lista de IPs (ex: 10.0.0.1,10.0.0.2)")
    parser.add_argument("--ips-file", help="Arquivo com lista de IPs (um por linha)")

    args = parser.parse_args()

    if not args.hosts_file:
        menu_principal()
        return

    show_banner()

    if not os.path.isfile(args.hosts_file):
        console.print(f"[red]Arquivo nao existe: {args.hosts_file}[/red]")
        sys.exit(1)

    hosts = carregar_hosts(args.hosts_file)
    if not hosts:
        console.print("[red]Nenhum host no arquivo[/red]")
        sys.exit(1)

    console.print(f"[cyan]Hosts L3 carregados: {len(hosts)}[/cyan]")

    if args.rede:
        ips = parse_ips(args.rede)
        console.print(f"[yellow]Modo: rede {args.rede}[/yellow]")
    elif args.range:
        ips = parse_ips(args.range)
        console.print(f"[yellow]Modo: range {args.range}[/yellow]")
    elif args.ips:
        ips = parse_ips(args.ips)
        console.print(f"[yellow]Modo: lista de IPs[/yellow]")
    elif args.ips_file:
        with open(args.ips_file, encoding="utf-8") as f:
            ips = [l.strip() for l in f if l.strip() and not l.startswith("#")]
        console.print(f"[yellow]Modo: arquivo de IPs ({args.ips_file})[/yellow]")
    else:
        entrada = Prompt.ask("[bold cyan]Informe a Rede (CIDR), Range ou IPs[/bold cyan]")
        ips = parse_ips(entrada)

    if not ips:
        console.print("[red]Nenhum IP valido[/red]")
        sys.exit(1)

    console.print(f"[cyan]Total IPs para verificar: {len(ips)}[/cyan]")
    if len(ips) > 50:
        console.print("[yellow]ATENCAO: Muitos IPs podem tornar o scan lento![/yellow]")

    user = Prompt.ask("[bold cyan]Usuario SSH[/bold cyan]")
    password = Prompt.ask("[bold cyan]Senha SSH[/bold cyan]", password=True)

    resultados = _executar_scan(hosts, user, password, ips, args.threads)
    _exibir_resultados(resultados, hosts, ips)

    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    exportar_csv_simples(resultados, f"ip-scanner-detalhado-{ts}.csv")
    exportar_csv_agrupado(resultados, f"ip-scanner-agrupado-{ts}.csv")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        STOP_EVENT.set()
        console.print("\n[yellow]Interrompido[/yellow]")
        sys.exit(0)
