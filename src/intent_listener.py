#!/usr/bin/env python2
import argparse
import grpc
import json
import os
import subprocess
import sys
import time

from collections import Counter
from time import sleep

from bm_runtime.simple_pre import SimplePre
from bm_runtime.standard import Standard
from bm_runtime.standard.ttypes import *
from flask import Flask, request
from thrift.protocol import TBinaryProtocol
from thrift.protocol import TMultiplexedProtocol
from thrift.transport import TSocket
from thrift.transport import TTransport
from p4codegen import P4CodeGenerator

# Import P4Runtime lib from parent utils dir
# Probably there's a better way of doing this.
sys.path.append(
    os.path.join(os.path.dirname(os.path.abspath(__file__)),
                 '../utils/'))
import p4runtime_lib.bmv2
import p4runtime_lib.helper
import p4runtime_lib.simple_controller
from p4runtime_lib.error_utils import printGrpcError
from p4runtime_lib.switch import ShutdownAllSwitchConnections

INTENT_FILENAME = "intent.txt"
app = Flask(__name__)

##############

def enum(type_name, *sequential, **named):
    enums = dict(zip(sequential, range(len(sequential))), **named)
    reverse = dict((value, key) for key, value in enums.iteritems())

    @staticmethod
    def to_str(x):
        return reverse[x]
    enums['to_str'] = to_str

    @staticmethod
    def from_str(x):
        return enums[x]

    enums['from_str'] = from_str
    return type(type_name, (), enums)

PreType = enum('PreType', 'None', 'SimplePre', 'SimplePreLAG')
MeterType = enum('MeterType', 'packets', 'bytes')
TableType = enum('TableType', 'simple', 'indirect', 'indirect_ws')
ResType = enum('ResType', 'table', 'action_prof', 'action', 'meter_array',
               'counter_array', 'register_array')

TABLES = {}
ACTION_PROFS = {}
ACTIONS = {}
METER_ARRAYS = {}
COUNTER_ARRAYS = {}
REGISTER_ARRAYS = {}
CUSTOM_CRC_CALCS = {}

# maps (object type, unique suffix) to object
SUFFIX_LOOKUP_MAP = {}

class MatchType:
    EXACT = 0
    LPM = 1
    TERNARY = 2
    VALID = 3
    RANGE = 4

    @staticmethod
    def to_str(x):
        return {0: "exact", 1: "lpm", 2: "ternary", 3: "valid", 4: "range"}[x]

    @staticmethod
    def from_str(x):
        return {"exact": 0, "lpm": 1, "ternary": 2, "valid": 3, "range": 4}[x]

class Table:
    def __init__(self, name, id_):
        self.name = name
        self.id_ = id_
        self.match_type_ = None
        self.actions = {}
        self.key = []
        self.default_action = None
        self.type_ = None
        self.support_timeout = False
        self.action_prof = None

        TABLES[name] = self

    def num_key_fields(self):
        return len(self.key)

    def key_str(self):
        return ",\t".join([name + "(" + MatchType.to_str(t) + ", " + str(bw) + ")" for name, t, bw in self.key])

    def table_str(self):
        ap_str = "implementation={}".format(
            "None" if not self.action_prof else self.action_prof.name)
        return "{0:30} [{1}, mk={2}]".format(self.name, ap_str, self.key_str())

    def get_action(self, action_name):
        key = ResType.action, action_name
        action = SUFFIX_LOOKUP_MAP.get(key, None)
        if action is None or action.name not in self.actions:
            return None
        return action

class ActionProf:
    def __init__(self, name, id_):
        self.name = name
        self.id_ = id_
        self.with_selection = False
        self.actions = {}
        self.ref_cnt = 0

        ACTION_PROFS[name] = self

    def action_prof_str(self):
        return "{0:30} [{1}]".format(self.name, self.with_selection)

    def get_action(self, action_name):
        key = ResType.action, action_name
        action = SUFFIX_LOOKUP_MAP.get(key, None)
        if action is None or action.name not in self.actions:
            return None
        return action

class Action:
    def __init__(self, name, id_):
        self.name = name
        self.id_ = id_
        self.runtime_data = []

        ACTIONS[name] = self

    def num_params(self):
        return len(self.runtime_data)

    def runtime_data_str(self):
        return ",\t".join([name + "(" + str(bw) + ")" for name, bw in self.runtime_data])

    def action_str(self):
        return "{0:30} [{1}]".format(self.name, self.runtime_data_str())

class MeterArray:
    def __init__(self, name, id_):
        self.name = name
        self.id_ = id_
        self.type_ = None
        self.is_direct = None
        self.size = None
        self.binding = None
        self.rate_count = None

        METER_ARRAYS[name] = self

    def meter_str(self):
        return "{0:30} [{1}, {2}]".format(self.name, self.size,
                                          MeterType.to_str(self.type_))

class CounterArray:
    def __init__(self, name, id_):
        self.name = name
        self.id_ = id_
        self.is_direct = None
        self.size = None
        self.binding = None

        COUNTER_ARRAYS[name] = self

    def counter_str(self):
        return "{0:30} [{1}]".format(self.name, self.size)

class RegisterArray:
    def __init__(self, name, id_):
        self.name = name
        self.id_ = id_
        self.width = None
        self.size = None

        REGISTER_ARRAYS[name] = self

    def register_str(self):
        return "{0:30} [{1}]".format(self.name, self.size)

def reset_config():
    TABLES.clear()
    ACTION_PROFS.clear()
    ACTIONS.clear()
    METER_ARRAYS.clear()
    COUNTER_ARRAYS.clear()
    REGISTER_ARRAYS.clear()
    CUSTOM_CRC_CALCS.clear()

    SUFFIX_LOOKUP_MAP.clear()

def load_json_str(json_str):
    def get_header_type(header_name, j_headers):
        for h in j_headers:
            if h["name"] == header_name:
                return h["header_type"]
        assert(0)

    def get_field_bitwidth(header_type, field_name, j_header_types):
        for h in j_header_types:
            if h["name"] != header_type: continue
            for t in h["fields"]:
                # t can have a third element (field signedness)
                f, bw = t[0], t[1]
                if f == field_name:
                    return bw
        assert(0)

    reset_config()
    json_ = json.loads(json_str)

    def get_json_key(key):
        return json_.get(key, [])

    for j_action in get_json_key("actions"):
        action = Action(j_action["name"], j_action["id"])
        for j_param in j_action["runtime_data"]:
            action.runtime_data += [(j_param["name"], j_param["bitwidth"])]

    for j_pipeline in get_json_key("pipelines"):
        if "action_profiles" in j_pipeline:  # new JSON format
            for j_aprof in j_pipeline["action_profiles"]:
                action_prof = ActionProf(j_aprof["name"], j_aprof["id"])
                action_prof.with_selection = "selector" in j_aprof

        for j_table in j_pipeline["tables"]:
            table = Table(j_table["name"], j_table["id"])
            table.match_type = MatchType.from_str(j_table["match_type"])
            table.type_ = TableType.from_str(j_table["type"])
            table.support_timeout = j_table["support_timeout"]
            for action in j_table["actions"]:
                table.actions[action] = ACTIONS[action]

            if table.type_ in {TableType.indirect, TableType.indirect_ws}:
                if "action_profile" in j_table:
                    action_prof = ACTION_PROFS[j_table["action_profile"]]
                else:  # for backward compatibility
                    assert("act_prof_name" in j_table)
                    action_prof = ActionProf(j_table["act_prof_name"],
                                             table.id_)
                    action_prof.with_selection = "selector" in j_table
                action_prof.actions.update(table.actions)
                action_prof.ref_cnt += 1
                table.action_prof = action_prof

            for j_key in j_table["key"]:
                target = j_key["target"]
                match_type = MatchType.from_str(j_key["match_type"])
                if match_type == MatchType.VALID:
                    field_name = target + "_valid"
                    bitwidth = 1
                elif target[1] == "$valid$":
                    field_name = target[0] + "_valid"
                    bitwidth = 1
                else:
                    field_name = ".".join(target)
                    header_type = get_header_type(target[0],
                                                  json_["headers"])
                    bitwidth = get_field_bitwidth(header_type, target[1],
                                                  json_["header_types"])
                table.key += [(field_name, match_type, bitwidth)]

    for j_meter in get_json_key("meter_arrays"):
        meter_array = MeterArray(j_meter["name"], j_meter["id"])
        if "is_direct" in j_meter and j_meter["is_direct"]:
            meter_array.is_direct = True
            meter_array.binding = j_meter["binding"]
        else:
            meter_array.is_direct = False
            meter_array.size = j_meter["size"]
        meter_array.type_ = MeterType.from_str(j_meter["type"])
        meter_array.rate_count = j_meter["rate_count"]

    for j_counter in get_json_key("counter_arrays"):
        counter_array = CounterArray(j_counter["name"], j_counter["id"])
        counter_array.is_direct = j_counter["is_direct"]
        if counter_array.is_direct:
            counter_array.binding = j_counter["binding"]
        else:
            counter_array.size = j_counter["size"]

    for j_register in get_json_key("register_arrays"):
        register_array = RegisterArray(j_register["name"], j_register["id"])
        register_array.size = j_register["size"]
        register_array.width = j_register["bitwidth"]

    for j_calc in get_json_key("calculations"):
        calc_name = j_calc["name"]
        if j_calc["algo"] == "crc16_custom":
            CUSTOM_CRC_CALCS[calc_name] = 16
        elif j_calc["algo"] == "crc32_custom":
            CUSTOM_CRC_CALCS[calc_name] = 32

    # Builds a dictionary mapping (object type, unique suffix) to the object
    # (Table, Action, etc...). In P4_16 the object name is the fully-qualified
    # name, which can be quite long, which is why we accept unique suffixes as
    # valid identifiers.
    # Auto-complete does not support suffixes, only the fully-qualified names,
    # but that can be changed in the future if needed.
    suffix_count = Counter()
    for res_type, res_dict in [
            (ResType.table, TABLES), (ResType.action_prof, ACTION_PROFS),
            (ResType.action, ACTIONS), (ResType.meter_array, METER_ARRAYS),
            (ResType.counter_array, COUNTER_ARRAYS),
            (ResType.register_array, REGISTER_ARRAYS)]:
        for name, res in res_dict.items():
            suffix = None
            for s in reversed(name.split('.')):
                suffix = s if suffix is None else s + '.' + suffix
                key = (res_type, suffix)
                SUFFIX_LOOKUP_MAP[key] = res
                suffix_count[key] += 1
    for key, c in suffix_count.items():
        if c > 1:
            del SUFFIX_LOOKUP_MAP[key]

#############

def run_external_program(shell_command):
    p = subprocess.Popen(shell_command, shell=True,
                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    for line in p.stdout.readlines():
        print line,
    return p.wait()

def generate_p4code_from_intent(intent_fname="intent.txt",
                                p4code_fname="s1_running.p4"):
    print "Reading intents from %s." % intent_fname
    gen = P4CodeGenerator(intent_fname)
    print "Parsing intents."
    gen.process_intents()
    print "Outputing p4 code to %s." % p4code_fname
    gen.generate_p4code(p4code_fname)

def process_new_p4code(topo_file="./topology.json",
                       p4info_file_path="./build/s1_running.p4info",
                       bmv2_file_path="./build/s1_running.json"):
    # Generate the new P4 code from intent.txt
    generate_p4code_from_intent()
    # Compile the P4 code into p4info and BMV2's JSON pipeline config files
    retval = run_external_program("p4c-bm2-ss --p4v 16 --p4runtime-file build/"
                                  "s1_running.p4info --p4runtime-format "
                                  "text -o build/s1_running.json s1_running.p4")

    # Read the topology and table content definition files
    with open(topo_file, 'r') as f:
        topo = json.load(f)
    switches = topo['switches']
    s1_runtime_json = switches['s1']['runtime_json']
    with open(s1_runtime_json, 'r') as sw_conf_file:
        s1_dict = p4runtime_lib.simple_controller.json_load_byteified(sw_conf_file)

    # Instantiate a P4Runtime helper from the p4info file
    p4info_helper = p4runtime_lib.helper.P4InfoHelper(p4info_file_path)

    try:
        # Create a switch connection object for s1 and s2;
        # this is backed by a P4Runtime gRPC connection.
        # Also, dump all P4Runtime messages sent to switch to given txt files.
        s1 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s1',
            address='127.0.0.1:50051',
            device_id=0,
            proto_dump_file='logs/s1-p4runtime-requests.txt')

        # Send master arbitration update message to establish this controller as
        # master (required by P4Runtime before performing any other write operation)
        s1.MasterArbitrationUpdate()

        # Install the P4 program on the switch
        s1.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                       bmv2_json_file_path=bmv2_file_path)
        print "Installed P4 Program using SetForwardingPipelineConfig on s1"

        # Install the table entries to the switch
        table_entries = s1_dict['table_entries']
        print "Inserting %d table entries..." % len(table_entries)
        for entry in table_entries:
            print p4runtime_lib.simple_controller.tableEntryToString(entry)
            p4runtime_lib.simple_controller.insertTableEntry(s1, entry, p4info_helper)
        print "Installed table entries on s1"

    except grpc.RpcError as e:
        printGrpcError(e)

    ShutdownAllSwitchConnections()


def load_json_config(standard_client=None, json_path=None):
    if json_path:
        if standard_client is not None:
            check_JSON_md5(standard_client, json_path)
        with open(json_path, 'r') as fh:
            return fh.read()
    else:
        assert(standard_client is not None)
        try:
            print "Obtaining JSON from switch..."
            json_cfg = standard_client.bm_get_config()
            print "Done"
        except:
            print "Error when requesting JSON config from switch\n"
            # sys.exit(1)
        return json_cfg


def thrift_connect(thrift_ip, thrift_port, services, out=sys.stdout):
    # Make socket
    transport = TSocket.TSocket(thrift_ip, thrift_port)
    # Buffering is critical. Raw sockets are very slow
    transport = TTransport.TBufferedTransport(transport)
    # Wrap in a protocol
    bprotocol = TBinaryProtocol.TBinaryProtocol(transport)

    clients = []

    for service_name, service_cls in services:
        if service_name is None:
            clients.append(None)
            continue
        protocol = TMultiplexedProtocol.TMultiplexedProtocol(bprotocol, service_name)
        client = service_cls(protocol)
        clients.append(client)

    # Connect!
    try:
        transport.open()
    except TTransport.TTransportException:
        print "Could not connect to thrift client ",
        print "on port %d" % thrift_port
        print "Make sure the switch is running ",
        print "and that you have the right port"
        # sys.exit(1)

    return clients

def get_res(type_name, name, res_type):
    key = res_type, name
    if key not in SUFFIX_LOOKUP_MAP:
        raise UIn_ResourceError(type_name, name)
    return SUFFIX_LOOKUP_MAP[key]


@app.route('/intent', methods=['POST'])
def process_intent():
    request.get_data()
    print "Received file content:"
    print request.data
    with open(INTENT_FILENAME, 'w') as fh:
        fh.write(request.data)

    # services = [("standard", Standard.Client), ("simple_pre", SimplePre.Client)]
    # standard_client, mc_client = thrift_connect("localhost", 9090, services)
    #
    # load_json_str(load_json_config(standard_client, None))
    # register_name = "regCountMinSketch"
    # register = get_res("register", register_name, ResType.register_array)
    #
    # print "Saving entire regCountMinSketch array values in controller.."
    # start_timer = time.time()
    # entries = standard_client.bm_register_read_all(0, register.name)
    # duration_save = time.time() - start_timer
    # print "{}=".format(register_name), ", ".join(
    #     ["%s(%s %s)" % (str(e), type(e), hex(e)) for e in entries])

    # Reload the pipeline!
    process_new_p4code()

    # load_json_str(load_json_config(standard_client, None))
    # register = get_res("register", register_name, ResType.register_array)

    # print "Writing back regCountMinSketch array values.."
    # Choose between Method 1 or 2!
    # # Method 1
    # start_timer = time.time()
    # for idx in xrange(len(entries)):
    #     standard_client.bm_register_write(0, register.name, idx, entries[idx])
    # duration_write = time.time() - start_timer

    # # Method 2
    # start_timer = time.time()
    # standard_client.bm_register_write_full(0, register.name,
    #                                        len(entries), entries)
    # duration_write = time.time() - start_timer
    #
    # print  "Save    : %.8f ms" % (duration_save*1000)
    # print  "Restore : %.8f ms" % (duration_write*1000)
    # print  "Total   : %.8f ms" % ((duration_save + duration_write)*1000)

    with open("s1_running.p4", 'r') as fh:
        p4code = fh.read()

    return json.dumps({'success': True, 'p4code': p4code}), 200


def main():
    host = "0.0.0.0"
    port = 5050
    app.run(host=host, port=port, debug=True)




if __name__ == '__main__':
    main()
