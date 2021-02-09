#!/usr/bin/env python3
# coding: utf-8
import os
import re
import csv
import sys
import json
import uuid
import socket
import hashlib
import argparse
import subprocess
from datetime import datetime
sys.path.append('/usr/tideway/python/common/')
import product

TW_FACTER_VERSION = '0.0.1'

if os.getenv('TW_FACTER_DRY_RUN'):
    try:
        TW_FACTER_DRY_RUN = int(os.getenv('TW_FACTER_DRY_RUN'))
    except:
        print(json.dumps({'status': 'error', 'message': 'TW_FACTER_DRY_RUN environment variable must be an integer!'}))
else:
    TW_FACTER_DRY_RUN = 60 # time in seconds

TW_TIDEWAY = '/usr/tideway'
TW_FACTER_USERNAME = 'tw_facter'
TW_FACTER_PASSWORD_FILE = '{}/.tw_facter_passwd'.format(TW_TIDEWAY)
TW_FACTER_CUSTOM_FACTS = '{}/.tw_facter_custom'.format(TW_TIDEWAY)
TW_FACTER_TIMESTAMP = '{}/.tw_facter_timestamp'.format(TW_TIDEWAY)
TW_FACTER_FACTS = '{}/.tw_facter_facts'.format(TW_TIDEWAY)

TW_CPU = '/proc/loadavg'
TW_MEM = '/proc/meminfo'

# docs: https://docs.bmc.com/docs/discovery/113/tw_service_control-800561100.html
TW_PERMISSIBLE_SERVICES = {'Application Server service': 'appserver',
                           'CMDB Sync (Exporter) service': 'cmdb_sync_exporter',
                           'CMDB Sync (Transformer) service': 'cmdb_sync_transformer',
                           'Discovery service': 'discovery',
                           'External API service': 'external_api',
                           'Mainframe Provider service': 'mainframe_provider',
                           'Model service': 'model',
                           'Reasoning service': 'reasoning',
                           'Reports service': 'reports',
                           'Security service': 'security',
                           'SQL Provider service': 'sql_provider',
                           'Tomcat service': 'tomcat',
                           'Vault service': 'vault'}

TW_POOL_HEADER = ['Pool', 'Type', 'Domains', 'IP Ranges']
TW_PROXIES_HEADER = ['Pool', 'Proxy', 'Address', 'Port', 'Type', 'Enabled', 'Active', 'Version']


""" BMC Discovery Queries """


TW_EXCLUDE_RANGES_QUERY = "search in '_System' ExcludeRange " \
                          "show " \
                          "name as 'name', " \
                          "range_strings as 'range_strings', " \
                          "description as 'description', " \
                          "recurrenceDescription(schedule) as 'schedule', " \
                          "enabled as 'enabled', " \
                          "fullFoundationName(created_by) as 'created_by', " \
                          "exrange_id as 'exrange_id', " \
                          "range_prefix as 'range_prefix'"

TW_SCHEDULED_RUNS = "search ScanRange where scan_type = 'Scheduled' " \
                    "show " \
                    "provider as 'cloud_provider', " \
                    "created_by as 'created_by', " \
                    "created_time as 'created_time', " \
                    "deleting as 'deleting', " \
                    "enabled as 'enabled', " \
                    "range_id as 'range_id', " \
                    "label as 'label', " \
                    "company as 'company', " \
                    "allow_tpl_scan as 'allow_tpl_scan', " \
                    "range_strings as 'range_strings', " \
                    "range_prefix as 'range_prefix', " \
                    "scan_kind as 'scan_kind', " \
                    "scan_level as 'scan_level', " \
                    "scan_type as 'scan_type', " \
                    "schedule as 'schedule', " \
                    "recurrenceDescription(schedule) as 'date_rules'"

TW_CURRENTLY_PROCESSING_RUNS = "search DiscoveryRun " \
                               "where __inprogress defined and not _consolidation_source defined " \
                               "order by starttime desc " \
                               "show " \
                               "blocked as blocked, " \
                               "cancelled as cancelled, " \
                               "_consolidation_source_name as _consolidation_source_name, " \
                               "_consolidation_source_system as _consolidation_source_system, " \
                               "_consolidation as _consolidation, " \
                               "consolidation_cancelled as consolidation_cancelled, " \
                               "_consolidation_last_received as _consolidation_last_received, " \
                               "_consolidation_done as _consolidation_done, " \
                               "_consolidation_source as _consolidation_source, " \
                               "discovery_endtime as discovery_endtime, " \
                               "discovery_starttime as discovery_starttime, " \
                               "has_eca_error as has_eca_error, " \
                               "endtime as endtime, " \
                               "valid_ranges as valid_ranges, " \
                               "failure_reason as failure_reason, " \
                               "hard_failure as hard_failure, " \
                               "key as key, " \
                               "label as label, " \
                               "cdm_company as cdm_company, " \
                               "consolidation_done_count as consolidation_done_count, " \
                               "done as done, " \
                               "scanning as scanning, " \
                               "explicit_ip_count as explicit_ip_count, " \
                               "pre_scanning as pre_scanning, " \
                               "waiting as waiting, " \
                               "implicit_ip_count as implicit_ip_count, " \
                               "range_prefix as range_prefix, " \
                               "range_summary as range_summary, " \
                               "scan_kind as scan_kind, " \
                               "scan_level as scan_level, " \
                               "scan_type as scan_type, " \
                               "starttime as starttime, " \
                               "total as total, " \
                               "user as user, " \
                               "done * 100 / total as percent_complete"


""" BMC Discovery Commands """


TW_USERNAME_PASSWORD = '--username={} --passwordfile={}'.format(TW_FACTER_USERNAME, TW_FACTER_PASSWORD_FILE)

# docs: https://docs.bmc.com/docs/discovery/113/tw_query-788110376.html
TW_QUERY_COMMAND = 'tw_query {}'.format(TW_USERNAME_PASSWORD)

# no vendor docs ; provide list of options set in BMC Discovery appliance
TW_OPTIONS_COMMAND = 'tw_options {}'.format(TW_USERNAME_PASSWORD)
TW_OPTIONS_COMMAND_DETAILS = '{} | ' \
                             'egrep -e \'\s+=\s+\' | ' \
                             'sed \'s/  = /=/g;s/  \+//g\''.format(TW_OPTIONS_COMMAND)

# docs: https://docs.bmc.com/docs/discovery/113/tw_listusers-788110363.html
TW_LISTUSERS_COMMAND = "tw_listusers | egrep -o '\\b^[a-zA-Z0-9@_+=-]+'"
TW_LISTUSERS_COMMAND_DETAILS = "tw_listusers --filter={}$ | " \
                               "egrep -v '{}:|^$' | " \
                               "sed 's/ \+/ /g;s/^ /#/g;s/: /%/g' | " \
                               "tr '\\n' ',' | " \
                               "sed 's/\(.*\),/\\1/;s/,#/#/g;s/:#/%/g;s/^#//g' | " \
                               "tr '#' '\\n' | " \
                               "sed -r ':r;/^user state/N;s/\\n/;/;tr' | " \
                               "sed 's/;password/\\npassword/g;s/;groups/\\ngroups/g'"

# docs: https://docs.bmc.com/docs/discovery/113/tw_vault_control-788110389.html
TW_VAULT_CONTROL_COMMAND = "tw_vault_control {} --show --json".format(TW_USERNAME_PASSWORD)

# docs: https://docs.bmc.com/docs/discovery/113/tw_service_control-800561100.html
TW_SERVICE_CONTROL_COMMAND = 'tw_service_control | ' \
                             'egrep -e \'\[\s+\w+\s+\]\' | ' \
                             'sed \'s/\[\s*/;/g;s/\s*\]//g;s/  \+//g;s/^ //g;s/:/;/g\''

# no vendor docs ; provide configuration related to the Administration/Security Policy (/ui/SetupSecurityOptions)
TW_SECOPTS_COMMAND = 'tw_secopts | ' \
                     'egrep -e \'\s+=\s+\' | ' \
                     'sed \'s/ = /=/g;s/  \+//g\''

# no vendor docs ; among other things provide configuration related Windows Pools and Proxies
TW_RESTRICTED_WINPROXY_COMMAND = 'tw_restricted_winproxy_ctrl {} {} > {}'

# provide information about tideway rpm's
TW_RPM = 'rpm -qa | grep tideway'
TW_RPM_DETAILS = "rpm -qi {} | sed '/^Description/N;s/\\n/ /'"

# provide information about cluster and omniNames services
TW_SYSTEMCTL_COMMAND = 'systemctl show -p LoadState,ActiveState,SubState,MainPID {} | ' \
                       'tr \'[:upper:]\' \'[:lower:]\' | ' \
                       'sed \'s/p/_p/g;s/st/_st/g\''

# provide information about taxonomy files, installed and custom
TW_TAXONOMY_COMMAND = 'find /usr/tideway/data/*/taxonomy/ -type f -iname "*.xsl" -o -iname "*.xml"'

# provide information about jdbc drivers, installed and custom
TW_JDBC_COMMAND = 'find /usr/tideway/data/*/jdbcdrivers/ -type f -iname "*.jar" -o -iname "*.properties"'

# provide information about file
TW_STAT_COMMAND = 'stat -c \'%A;%U;%G\' {}'

# system
# network information
TW_SYSTEM_NETWORK_GET_PRIMARY_INTERFACE = "route | awk '/^default/{print $NF}'"
TW_SYSTEM_NETWORK_GET_IP_ADDRESS = "ip route show | grep -Po '(?<=(src )).*(?= metric)'"
TW_SYSTEM_NETWORK_GET_GATEWAY = "ip route show | grep -Po '(?<=(default via )).*(?= dev)'"
# uptime
TW_SYSTEM_UPTIME = "awk '{print $1}' /proc/uptime"
# uname
TW_SYSTEM_UNAME = "uname -a"

# cores
TW_CORES_COUNT = "find /usr/tideway/cores/ -iname 'core.*' | wc -l"
TW_CORES_SIZE = "du -h /usr/tideway/cores | awk '{print $1}'"

""" tw_facter functions """


def main(facts=None):
    parser = argparse.ArgumentParser()

    parser.add_argument('-d', '--dry', action='store_true', help='Dry run')
    parser.add_argument('-k', '--kind', default=['all'], choices=['appliance', 'cluster', 'custom', 'cores', 'discovery',
                                                                  'env', 'facter', 'jdbc', 'metadata', 'omninames',
                                                                  'options', 'rpms', 'security', 'services', 'system',
                                                                  'taxonomy', 'users', 'vault', 'windows'],
                        help='Shows selected kinds', nargs='+')
    parser.add_argument('-v', '--version', action='store_true', help='Shows tw_facter version')

    args = parser.parse_args()

    if args.version:
        print('tw_facter v{}'.format(TW_FACTER_VERSION))
    elif args.dry or dry_run():
        facts = tw_facts(args.kind)
        tw_facts_write(facts)
    else:
        facts = tw_facts_read()

    if facts:
        print(json.dumps(facts, sort_keys=True))


def dry_run():
    prev = 0
    now = int(datetime.now().timestamp())

    if os.path.isfile(TW_FACTER_TIMESTAMP):
        prev = int(open(TW_FACTER_TIMESTAMP, mode='r').read())

    with open(TW_FACTER_TIMESTAMP, mode='w') as file:
        file.write(str(now))

    if now - prev > TW_FACTER_DRY_RUN:
        return True
    return False


def appliance():
    _dict = {}
    for item in product.__dict__:
        if item.isupper() and not re.search('COPYRIGHT', item):
            _dict[item.lower()] = product.__dict__[item]
    hostname = socket.gethostname()
    ip = socket.gethostbyname_ex(hostname)[-1]
    fqdn = socket.getfqdn()
    return {'ip': ip,
            'hostname': hostname,
            'fqdn': fqdn,
            'product': _dict}


def cluster():
    return exec_systemctl('cluster')


def custom():
    _dict = {}
    if os.path.isfile(TW_FACTER_CUSTOM_FACTS):
        with open(TW_FACTER_CUSTOM_FACTS, 'r') as f:
            array = f.read().splitlines()

        for item in array:
            k, v = item.split('=')
            _dict[k] = v
    return _dict


def cores():
    def count():
        return exec(TW_CORES_COUNT)[0]

    def size():
        return exec(TW_CORES_SIZE)[0]

    return {'count': count(),
            'size': size()}


def discovery():
    def exclude_ranges():
        return convert_to_list_of_dicts(exec_tw_query(TW_EXCLUDE_RANGES_QUERY))

    def scheduled_runs():
        return convert_to_list_of_dicts(exec_tw_query(TW_SCHEDULED_RUNS))

    def currently_processing_runs():
        return convert_to_list_of_dicts(exec_tw_query(TW_CURRENTLY_PROCESSING_RUNS))

    return {'exclude_ranges': exclude_ranges(),
            'scheduled_runs': scheduled_runs(),
            'currently_processing_runs': currently_processing_runs()}


def env():
    _dict = {}
    for env in os.environ:
        _dict[env] = os.getenv(env)
    return _dict


def facter():
    return {'version': TW_FACTER_VERSION,
            'id': os.getegid(),
            'gid': os.getuid()}


def jdbc():
    _dict = {}
    custom = []
    installed = []
    for item in exec(TW_JDBC_COMMAND):
        stat = file_stat_details(item)
        if re.search('properties', item):
            content = {}
            for property in convert_to_list(item, False):
                property = property.split('=')
                k = property[0]
                v = ''.join(property[1:])
                content[k] = v
            stat['content'] = content
        custom.append(stat) if re.search('custom', item) else installed.append(stat)
    _dict['custom'] = custom
    _dict['installed'] = installed
    return _dict


def metadata():
    def timestamp_strftime(time):
        return time.strftime('%Y-%m-%d %H:%M:%S')

    def timestamp():
        now = datetime.now()
        now_utc = now.utcnow()
        return {'now': timestamp_strftime(now),
                'now_utc': timestamp_strftime(now_utc)}

    return {'timestamp': timestamp(),
            'id': message_id()}


def omninames():
    return exec_systemctl('omniNames')


def options():
    _dict = {}
    for item in exec(TW_OPTIONS_COMMAND_DETAILS):
        item = item.split('=')
        k = item[0]
        v = ''.join(item[1:])
        _dict[k] = v
    return _dict


def rpms():
    def rpms_list():
        return exec(TW_RPM)

    _array = []
    for rpm in rpms_list():
        rpm_dict = {}
        item = exec(TW_RPM_DETAILS.format(rpm))
        for detail in item:
            detail = detail.split(':')
            k = detail[0].strip().replace(' ', '_').lower()
            v = ''.join(detail[1:]).strip()
            rpm_dict[k] = v
        _array.append(rpm_dict)
    return _array


def security():
    _dict = {}
    for item in exec(TW_SECOPTS_COMMAND):
        k = item.split('=')[0]
        v = ''.join(item.split('=')[1:])
        _dict[k] = v
    return _dict


def services():
    _dict = {}
    for service in exec(TW_SERVICE_CONTROL_COMMAND):
        name, pid, status = service.split(';')
        _dict[TW_PERMISSIBLE_SERVICES[name]] = {'name': name,
                                                'pid': pid,
                                                'status': status}
    return _dict


def system():
    def network():
        def get_primary_interface():
            return exec(TW_SYSTEM_NETWORK_GET_PRIMARY_INTERFACE)[0]

        def get_ip_address():
            return exec(TW_SYSTEM_NETWORK_GET_IP_ADDRESS)[0]

        def get_gateway():
            return exec(TW_SYSTEM_NETWORK_GET_GATEWAY)[0]

        return {'interface': get_primary_interface(),
                'ip_address': get_ip_address(),
                'gateway': get_gateway()}

    def uptime():
        return exec(TW_SYSTEM_UPTIME)[0]

    def uname():
        return exec(TW_SYSTEM_UNAME)[0]

    def cpu():
        with open(TW_CPU, 'r') as f:
            return f.read().strip().split()[0:3]

    def getmem(meminfo, item):
        return re.findall('[0-9]+', ' '.join(meminfo[item].strip().split()))[0]

    def mem():
        with open(TW_MEM, 'r') as f:
            meminfo = f.readlines()

        return {'total_kb': getmem(meminfo, 0),
                'free_kb': getmem(meminfo, 1),
                'available_kb': getmem(meminfo, 2)}

    def rh():
        return exec('cat /etc/redhat-release')[0]

    return {'uptime': uptime(),
            'cpu': cpu(),
            'mem': mem(),
            'network': network(),
            'os': rh(),
            'uname': uname()}


def taxonomy():
    _dict = {}
    custom = []
    installed = []
    for item in exec(TW_TAXONOMY_COMMAND):
        stat = file_stat_details(item)
        custom.append(stat) if re.search('custom', item) else installed.append(stat)
    _dict['custom'] = custom
    _dict['installed'] = installed
    return _dict


def users():
    def users_list():
        return exec(TW_LISTUSERS_COMMAND)

    _dict = {}
    for user in users_list():
        user_dict = {}
        item = exec(TW_LISTUSERS_COMMAND_DETAILS.format(user, user))
        for detail in item:
            if len(detail.split('%')) == 2:
                k, v = detail.split('%')
                user_dict[k.replace(' ', '_')] = v
            else:
                item_dict = {}
                detail = detail.split(';')
                for item in detail:
                    k, v = item.split('%')
                    k = k.lower().replace(' ', '_').replace('password', 'value').replace('user_state', 'state')
                    v = v.replace('\"', '')
                    item_dict[k] = v
                if any('user state' in i for i in detail):
                    user_dict['user'] = item_dict
                if any('password' in i for i in detail):
                    user_dict['password'] = item_dict
        _dict[user] = user_dict
    return _dict


def vault():
    _array = []
    for credential in exec(TW_VAULT_CONTROL_COMMAND):
        if 'types' in credential:
            _array.append(json.loads(credential))
    return _array


def windows():
    def win_details(file, headers, type=None):
        if type == 'pool':
            global number_of_pools
            number_of_pools = 0
        if type == 'proxy':
            global number_of_proxies, number_of_proxies_enabled, number_of_proxies_active, number_of_proxies_disabled, number_of_proxies_inactive
            number_of_proxies = 0
            number_of_proxies_enabled = 0
            number_of_proxies_disabled = 0
            number_of_proxies_active = 0
            number_of_proxies_inactive = 0
        tw_header_position = []
        results = []
        array = convert_to_list(file)

        for header in headers:
            try:
                tw_header_position.append(array[0].find(header))
            except:
                pass

        for item in array[1:]:
            _dict = {}
            for i in range(len(tw_header_position)):
                start = tw_header_position[i]
                try:
                    end = tw_header_position[i + 1]
                except:
                    end = None
                k = headers[i].lower().replace(' ', '_')
                v = item[start:end].strip()
                _dict[k] = v
                if type == 'proxy':
                    if headers[i] == 'Enabled' and _dict[headers[i].lower()] == 'True':
                        number_of_proxies_enabled += 1
                    if headers[i] == 'Active' and _dict[headers[i].lower()] == 'True':
                        number_of_proxies_active += 1
                    if headers[i] == 'Enabled' and _dict[headers[i].lower()] == 'False':
                        number_of_proxies_disabled += 1
                    if headers[i] == 'Active' and _dict[headers[i].lower()] == 'False':
                        number_of_proxies_inactive += 1
            results.append(_dict)

        if type == 'pool':
            number_of_pools = len(array[1:])
        if type == 'proxy':
            number_of_proxies = len(array[1:])

        return results


    def win(type):
        command_results = '/tmp/tw_facter_{}'.format(message_id())
        if type == 'pool':
            switch = '--list-all-pools'
            header = TW_POOL_HEADER
        elif type == 'proxy':
            switch = '--list-all-proxies'
            header = TW_PROXIES_HEADER
        exec(TW_RESTRICTED_WINPROXY_COMMAND.format(TW_USERNAME_PASSWORD, switch, command_results))
        return win_details(command_results, header, type)


    def windows_pools():
        return win('pool')


    def windows_proxies():
        return win('proxy')

    return {'pools': windows_pools(),
            'proxies': windows_proxies(),
            'number_of_pools': number_of_pools,
            'number_of_proxies': number_of_proxies,
            'number_of_proxies_enabled': number_of_proxies_enabled,
            'number_of_proxies_disabled': number_of_proxies_disabled,
            'number_of_proxies_active': number_of_proxies_active,
            'number_of_proxies_inactive': number_of_proxies_inactive}


def tw_facts(kind):
    if 'all' in kind:
        return {'appliance': appliance(),
                'cluster': cluster(),
                'custom': custom(),
                'cores': cores(),
                'discovery': discovery(),
                'env': env(),
                'facter': facter(),
                'jdbc': jdbc(),
                'metadata': metadata(),
                'omninames': omninames(),
                'options': options(),
                'rpms': rpms(),
                'security': security(),
                'services': services(),
                'system': system(),
                'taxonomy': taxonomy(),
                'users': users(),
                'vault': vault(),
                'windows': windows()}
    else:
        _return = {}
        for _ in kind:
            _return[_] = globals()[_]()
        return _return


""" tw_facter helpers """


def tw_facts_read():
    with open(TW_FACTER_FACTS, mode='r') as file:
        return json.loads(file.read())


def tw_facts_write(facts):
    with open(TW_FACTER_FACTS, mode='w') as file:
        file.write(json.dumps(facts, sort_keys=True))


def file_stat_details(file):
    def file_stat(file):
        return exec(TW_STAT_COMMAND.format(file))

    _dict = {}
    permissions, user, group = file_stat(file)[0].split(';')
    _dict['file'] = os.path.basename(file)
    _dict['md5sum'] = file_md5sum(file)
    _dict['permissions'] = permissions
    _dict['user'] = user
    _dict['group'] = group
    return _dict


def file_md5sum(file):
    return hashlib.md5(open(file, 'rb').read()).hexdigest()


def message_id():
    return uuid.uuid4().hex


def exec(command):
    result = subprocess.Popen(command,
                              stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE,
                              shell=True,
                              universal_newlines=True,
                              bufsize=0)
    _array = []
    for line in result.stdout:
        _array.append(line.strip())
    return _array


def exec_tw_query(query):
    command_results = '/tmp/tw_facter_{}'.format(message_id())
    command = '{} --csv "{}" > {}'.format(TW_QUERY_COMMAND, query, command_results)
    exec(command)
    return command_results


def exec_systemctl(service):
    _dict = {}
    for item in exec(TW_SYSTEMCTL_COMMAND.format(service)):
        k, v = item.split('=')
        _dict[k.lower()] = v
    return _dict


def convert_to_list_of_dicts(file):
    _array = []
    with open(file, mode='r') as csv_file:
        csv_reader = csv.DictReader(csv_file)
        for item in csv_reader:
            _array.append(item)
    os.remove(file)
    return _array


def convert_to_list(file, remove=True):
    with open(file, mode='r') as tab_file:
        array = tab_file.read().strip().splitlines()
        os.remove(file) if remove else None
    return array


if __name__ == '__main__':
    sys.exit(main())
