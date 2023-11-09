import time
import json
import random
import hashlib
import argparse
import datetime
import warnings
import collections.abc
import subprocess
from itertools import cycle

from scapy.utils import PcapWriter
from colorama import Fore, Style, init as Init
from scapy.all import sniff, load_layer, Ether, bind_layers, TCP

# Ignora l'avviso:
# CryptographyDeprecationWarning:
# Il supporto per la creazione non sicura di numeri pubblici
# da dati codificati verrà rimosso in una versione futura.
# Si prega di utilizzare EllipticCurvePublicKey.from_encoded_point
warnings.filterwarnings('ignore')

# Inizializza il modulo Colorama per la gestione dei colori in console
Init()

# Funzione per ottenere un attributo da un oggetto con un valore predefinito
def get_attr(obj, attr, default=""):
    value = getattr(obj, attr, default)
    if value is None:
        value = default
    return value

# Funzione per formattare il tempo in unità leggibili
def timer_unit(s):
    if s <= 1:
        return f'{round(s, 1)}s'

    num, unit = [
        (i, u) for i, u in ((s / 60**i, u) for i, u in enumerate('smhd')) if i >= 1
    ][-1]

    return f'{round(num, 1)}{unit}'

# Funzione per colorare il testo in console
def put_color(string, color, bold=True):
    if color == 'gray':
        COLOR = Style.DIM+Fore.WHITE
    else:
        COLOR = getattr(Fore, color.upper(), "WHITE")

    return f'{Style.BRIGHT if bold else ""}{COLOR}{str(string)}{Style.RESET_ALL}'

# Funzione per stampare il risultato in console o salvarlo su file
def Print(data):
    if output_filename == 'stdout':
        if need_json:
            print(' '*15, '\r' + json.dumps(data, indent=4,), end='\n\n')
        else:
            print(data, end='\n\n')
    else:
        if need_json:
            with open(output_filename, 'a') as fp:
                json.dump(data, fp)
                fp.write('\n')
        else:
            with open(output_filename, 'a') as fp:
                fp.write(data+'\n')

# Funzione per concatenare i dati in una stringa formattata
def concat(data, delete_grease=False):
    result = []
    for i, d in enumerate(data):
        if isinstance(d, collections.abc.Iterable):
            result.append('-'.join(map(
                str,
                remove_grease(d) if delete_grease else d
            )))
        else:
            result.append(str(d))

    return ','.join(result)

# Funzione per rimuovere i valori GREASE (valori non validi per la fingerprint)
def remove_grease(value):
    return [i for i in value if i not in GREASE_TABLE]

# Funzione per caricare la blacklist da un file
def load_blacklist(file_path):

    try:
        with open(file_path, 'r') as f:
            return set(f.read().splitlines())
    except FileNotFoundError:
        print(f"[!] File '{file_path}' not found.")
        return set()

# Funzione per salvare la blacklist su file
def save_blacklist(file_path, data):
    with open(file_path, 'w') as f:
        f.write('\n'.join(data))

# Funzione per verificare se una fingerprint corrisponde alla blacklist JA3
def is_matching_ja3(ja3):
    if ja3 in blacklist:
        return True
    return False

# Funzione per verificare se un indirizzo IP corrisponde alla seconda blacklist
def is_matching_second_blacklist(src_ip):
    if src_ip in second_blacklist:
        return True
    return False

# Funzione per bloccare una connessione utilizzando iptables
def block_connection(src_ip):
    subprocess.run(["iptables", "-A", "INPUT", "-s", src_ip, "-j", "DROP"])

# Funzione per analizzare i pacchetti
def collector(pkt):
    global COUNT, COUNT_SERVER, COUNT_CLIENT, NEW_BIND_PORTS

    COUNT += 1

    if savepcap:
        pcap_dump.write(pkt)

    print(f'[*] running... {put_color(next(roll), "green")}', end='\r')

    tcp_layer = pkt.getlayer('TCP')
    if tcp_layer is None:
        return

    IP_layer = pkt.getlayer("IP") or pkt.getlayer("IPv6")

    src_ip = IP_layer.src
    src_port = pkt.getlayer("TCP").sport

    dst_ip = IP_layer.dst
    dst_port = pkt.getlayer("TCP").dport

    layer = get_attr(tcp_layer[0], 'msg')
    if not layer:
        if pkt.lastlayer().name != 'Raw':
            return

        if src_port in NEW_BIND_PORTS[0] and dst_port in NEW_BIND_PORTS[1]:
            return

        bind_layers(TCP, TLS, sport=src_port)  # noqa: F821
        bind_layers(TCP, TLS, dport=dst_port)  # noqa: F821

        NEW_BIND_PORTS[0].add(src_port)
        NEW_BIND_PORTS[1].add(dst_port)

        pkt = Ether(pkt.do_build())
        tcp_layer = pkt.getlayer('TCP')
        layer = get_attr(tcp_layer[0], 'msg')
        if not layer:
            return

    layer = layer[0]
    name = layer.name

    if not name.endswith('Hello'):
        return

    from_type = 0
    from_name = 'Server'
    fp_name = 'ja3s'

    if name.startswith('TLS') or name.startswith('SSL'):
        if 'Client' in name:
            if ja3_type not in ["ja3", "all"]:
                # filtro ja3
                return

            from_type = 1
            from_name = 'Client'
            fp_name = 'ja3'

        elif ja3_type not in ["ja3s", "all"]:
            # filtro ja3s
            return
    else:
        return

    server_name = 'unknown'

    Version = layer.version
    Cipher = get_attr(layer, 'ciphers' if from_type else 'cipher')

    exts = get_attr(layer, 'ext')
    if exts:
        Extensions_Type = list(map(lambda c: c.type, exts))

        if from_type:
            try:
                loc = Extensions_Type.index(0)
            except ValueError:
                server_name = 'unknown'
            else:
                server_names = get_attr(exts[loc], 'servernames')

                if server_names:
                    server_name = get_attr(
                        server_names[0],
                        'servername', 'unknown'
                    ).decode('utf8')

            try:
                loc = Extensions_Type.index(11)
            except IndexError:
                EC_Point_Formats = []
            else:
                EC_Point_Formats = get_attr(exts[loc], 'ecpl')

            try:
                loc = Extensions_Type.index(10)
            except IndexError:
                Elliptic_Curves = []
            else:
                Elliptic_Curves = get_attr(exts[loc], 'groups')

    else:
        Extensions_Type = Elliptic_Curves = EC_Point_Formats = []

    if from_type:
        COUNT_CLIENT += 1
        value = [
            Version, Cipher, Extensions_Type,
            Elliptic_Curves, EC_Point_Formats
        ]

    else:
        COUNT_SERVER += 1
        value = [Version, Cipher, Extensions_Type]

    raw_fp = concat(value)
    raw_fp_no_grease = concat(value, delete_grease=True)

    md5_fp = hashlib.md5(raw_fp.encode('utf8')).hexdigest()
    md5_fp_no_grease = hashlib.md5(raw_fp_no_grease.encode('utf8')).hexdigest()

    handshake_type = name.split(' ')[0]
    is_match = is_matching_ja3(md5_fp)
    is_second_match = is_matching_second_blacklist(src_ip)

    if is_match:
        block_connection(src_ip)
        if not is_second_match:
            second_blacklist.add(src_ip)
            save_blacklist(second_blacklist_file, second_blacklist)

    if need_json:
        json_data = {
            'from': from_name,
            'type': handshake_type,
            'src': {
                'ip': src_ip,
                'port': src_port,
            },
            'dst': {
                'ip': dst_ip,
                'port': dst_port,
            },
            fp_name: {
                'str': raw_fp,
                'md5': md5_fp,
                'str_no_grease': md5_fp_no_grease,
                'md5_no_grease': md5_fp_no_grease,
            },
            'is_match': is_match,
            'is_second_match': is_second_match
        }

        if from_type:
            json_data['dst']['server_name'] = server_name

        Print(json_data)
    else:
        color_data = '\n'.join([
            f'[+] Hello from {put_color(from_name, "cyan", bold=False)}',
            f'  [-] type: {put_color(handshake_type, "green")}',
            f'  [-] src ip: {put_color(src_ip, "cyan")}',
            f'  [-] src port: {put_color(src_port, "white")}',
            f'  [-] dst ip: {put_color(dst_ip, "blue")}' + (
                f' ({put_color(server_name, "white")})' if from_type else ''
            ),
            f'  [-] dst port: {put_color(dst_port, "white")}',
            f'  [-] {fp_name}: {raw_fp}',
            f'  [-] {fp_name}_no_grease: {raw_fp_no_grease}',
            f'  [-] md5: {put_color(md5_fp, "yellow")}',
            f'  [-] md5_no_grease: {put_color(md5_fp_no_grease, "yellow")}',
            f'  [-] Match: {put_color("Yes", "green") if is_match else put_color("No", "red")}',
            f'  [-] Second Match: {put_color("Yes", "green") if is_second_match else put_color("No", "red")}',
        ])
        Print(color_data)

# Inizio dello script

VERSION = '2.2'

# Stampa il logo del tool
print(f'''
{Style.BRIGHT}{Fore.YELLOW}  ________
{Style.BRIGHT}{Fore.YELLOW} [__,.,--\\\\{Style.RESET_ALL} __     ______
{Style.BRIGHT}{Fore.YELLOW}    | |    {Style.RESET_ALL}/ \\\\   |___ //
{Style.BRIGHT}{Fore.YELLOW}    | |   {Style.RESET_ALL}/ _ \\\\    |_ \\\\
{Style.BRIGHT}{Fore.YELLOW}  ._| |  {Style.RESET_ALL}/ ___ \\\\  ___) ||  
{Style.BRIGHT}{Fore.YELLOW}  \\__// {Style.RESET_ALL}/_//  \\_\\\\|____//   
''')

# Parsing degli argomenti da linea di comando
parser = argparse.ArgumentParser(description='Running in Py3.x')
parser.add_argument(
    "-i", default='Any',
    help="interface or list of interfaces (default: sniffing on all interfaces)"
)
parser.add_argument(
    "-f", default=None,
    help="local pcap filename (in the offline mode)"
)
parser.add_argument(
    "-of", default='stdout',
    help="choose where to print the results (default: stdout)"
)
parser.add_argument(
    "-bpf", default="(tcp[tcp[12]/16*4]=22) and (tcp[tcp[12]/16*4+9]=3) and (tcp[tcp[12]/16*4+1]=3)", help="Don't change this filter if u want to get the Client/Server Hello Packets"
)

parser.add_argument(
    "-jtype", default="all",
    choices=["ja3", "ja3s", "all"], help="Choose ja3 or ja3s (default:all)"
)

parser.add_argument("--json", action="store_true", help="print result as json")
parser.add_argument(
    "--savepcap", action="store_true",
    help="save the raw pcap"
)
parser.add_argument(
    "-pf",
    default=datetime.datetime.now().strftime("%Y.%m.%d-%X"),
    help="eg. `-pf test`: save the raw pcap as test.pcap"
)

parser.add_argument(
    "--ja3blacklist", default=None,
    help="path to the file containing the JA3 blacklist"
)

parser.add_argument(
    "--IPblacklist", default=None,
    help="path to the file containing the IP blacklist"
)

args = parser.parse_args()

COUNT = COUNT_SERVER = COUNT_CLIENT = 0
GREASE_TABLE = {
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a,
    0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
    0x8a8a, 0x9a9a, 0xaaaa, 0xbaba,
    0xcaca, 0xdada, 0xeaea, 0xfafa
}

NEW_BIND_PORTS = [set(), set()]
roll = cycle('\\|-/')

bpf = args.bpf
need_json = args.json
output_filename = args.of
savepcap = args.savepcap
pcap_filename = args.pf
iface = args.i
ja3_type = args.jtype

if savepcap:
    pcap_dump = PcapWriter(
        f'{pcap_filename}.pcap',
        append=True,
        sync=True
    )

if args.ja3blacklist:
    blacklist_file = args.ja3blacklist
    blacklist = load_blacklist(blacklist_file)
    print(f'[*] Loaded ja3blacklist from: {put_color(blacklist_file, "white")} with {put_color(len(blacklist), "cyan")} entries')
else:
    print('[!] No blacklist file specified. The blacklist will be empty.')
    blacklist = set()

if args.IPblacklist:
    second_blacklist_file = args.IPblacklist
    second_blacklist = load_blacklist(second_blacklist_file)
    print(f'[*] Loaded IPblacklist from: {put_color(second_blacklist_file, "white")} with {put_color(len(second_blacklist), "cyan")} entries')
else:
    print('[!] No second blacklist file specified. The second blacklist will be empty.')
    second_blacklist = set()

# Impostazione degli argomenti per la funzione sniff()
sniff_args = {
    'prn': collector,
    'filter': bpf,
    'store': 0,
    'iface': iface if iface != 'Any' else None,
}

if args.f:
    # Modalità offline: leggi i pacchetti da un file pcap
    filename = args.f
    offline = filename

    sniff_args['offline'] = filename

    print(f'[*] mode: {put_color("offline", "yellow")}')
    print(f'[*] filename: {put_color(filename, "white")}', end='\n\n')

else:
    # Modalità online: cattura i pacchetti in tempo reale dalle interfacce di rete
    print(f'[*] mode: {put_color("online", "green")}')
    print(f'[*] iface: {put_color(iface, "white")}', end='\n\n')

print(f'[*] BPF: {put_color(bpf, "white")}')
print(f'[*] type filter: {put_color(ja3_type, "white")}')
print(f'[*] output filename: {put_color(output_filename, "white")}')
print(f'[*] output as json: {put_color(need_json, "green" if need_json else "white", bold=False)}')
print(f'[*] save raw pcap: {put_color(savepcap, "green" if savepcap else "white", bold=False)}')

if savepcap:
    print(f'[*] saved in: {put_color(pcap_filename, "white")}.pcap')

print()

load_layer("tls")

start_ts = time.time()

try:
    # Avvio della cattura e analisi dei pacchetti
    sniff(**sniff_args)
except Exception as e:
    print(f'[!] {put_color(f"Something went wrong: {e}", "red")}')

end_ts = time.time()
print(
    '\r[+]',
    f'all packets: {put_color(COUNT, "cyan")};',
    f'client hello: {put_color(COUNT_CLIENT, "cyan")};',
    f'server hello: {put_color(COUNT_SERVER, "cyan")};',
    f'in {put_color(timer_unit(end_ts-start_ts), "white")}'
)

print(
    '\n\r[*]',
    put_color(
        random.choice([
            u"goodbye", u"have a nice day", u"see you later",
            u"farewell", u"cheerio", u"bye",
        ])+random.choice(['...', '~~', '!', ' :)']), 'green'
    )
)

