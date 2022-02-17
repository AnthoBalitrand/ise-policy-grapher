import xmltodict
import os
import json
import sys
import networkx as nx
import pyyed

output_dir = './outputs'
policy_graph = nx.DiGraph()

cisco_default_conditions = [
    "Guest_Flow",
    "EAP-TLS",
    "EAP-MSCHAPv2",
    "BYOD_is_Registered",
    "Wireless_Access",
    "Non_Cisco_Profiled_Phones",
    "Compliant_Devices",
    "Non_Compliant_Devices",
    "Compliance_Unknown_Devices",
    "WLC_Web_Authentication",
    "Wireless_MAB",
    "Wired_802.1X",
    "Network_Access_Authentication_Passed",
    "MAC_in_SAN",
    "Wired_MAB",
    "Switch_Web_Authentication",
    "Catalyst_Switch_Local_Web_Authentication",
    "Wireless_802.1X",
    "Switch_Local_Web_Authentication",
    "CertRenewalRequired"
]

cisco_default_authprofiles = [
    "Non_Cisco_IP_Phones",
    "NSP_Onboard",
    "Cisco_WebAuth",
    "Cisco_IP_Phones",
    "Blackhole_Wireless_Access",
    "DenyAccess",
    "PermitAccess",
    "UDN"
]

profile_status = {
    'true': 'ENABLED',
    'false': 'DISABLED'
}

def main():
    if len(sys.argv) > 1:
        input_file = sys.argv[1]
    else:
        print("No input file provided")
        exit(0)

    if os.path.exists(input_file):
        # open input file
        with open(input_file) as pf:
            try:
                # convert input file to json format
                pxml = xmltodict.parse(pf.read())
                print("Policy file loaded")
                # store converted input on pjson object
                pjson = json.loads(json.dumps(pxml))

                # if input file contains libraryConditions --> version is >= 2.6
                if pjson.get('Root', dict()).get('libraryConditions'):
                    policy_analyzer(pjson['Root'])
                # else version is < 2.6
                elif pjson.get('Root', dict()).get('ReusableConditions'):
                    print("ISE_Policy_Grapher is not compatible with ISE < 2.6 policies")
                else:
                    print("Malformated input file or unhandled ISE version")
                exit(0)
            except Exception as e:
                exc_type, exc_obj, exc_tb = sys.exc_info()
                fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
                print(f"Encountered exception while opening policy file : {e} {exc_type} {fname} {exc_tb.tb_lineno}")
            finally:
                # close input file
                pf.close()
    else:
        print(f"Unable to find input file at {input_file!r}\n")

    return 0


def flatten_references(obj):
    children_ref_list = list()
    if type(obj) == dict:
        if obj.get('refId'):
            children_ref_list.append(obj.get('refId'))
        elif obj.get('children'):
            children_ref_list += flatten_references(obj.get('children'))
    elif type(obj) == list:
        for i in obj:
            children_ref_list += flatten_references(i)
    return children_ref_list


def listify(obj):
    # returns input object as a new list first (and only) member if this object is not already a list
    return obj if isinstance(obj, list) else [obj] if not isinstance(obj, type(None)) else []


def find_ref(name, cond):
    # checks if object "name" appears in referenced conditions of object "cond"
    res = False
    for ref in cond['references']:
        if ref['name'] == name:
            res = True
    return res


def populate_references(cond, bases):
    global conditions_map
    if len(bases) > 0:
        for c in conditions_map:
            if find_ref(cond['name'], c):
                c['references'] += bases
                populate_references(c, bases)


def init_conditions(policy_conditions):
    global policy_graph
    try:
        print(f"{len(policy_conditions)} conditions found on Condition Library\n")
        print("Populating graph conditions nodes...")
        for x in policy_conditions:
            policy_graph.add_node(
                "C_"+x['libraryCondition']['name'],
                name=x['libraryCondition']['name'],
                type="condition")

        print("Populating graph conditions edges...")
        for x in policy_conditions:
            refs = flatten_references(x['libraryCondition']['condition']['children'])
            policy_graph.add_edges_from([("C_"+y, "C_"+x['libraryCondition']['name']) for y in refs])
    except Exception as e:
        exc_type, exc_obj, exc_tb = sys.exc_info()
        fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
        print(f"Encountered exception : {e} {exc_type} {fname} {exc_tb.tb_lineno}")


def init_auth_profiles(policy_profiles):
    global policy_graph
    try:
        print(f"{len(policy_profiles)} profiles found on AznResult library\n")
        print("Populating graph with authorization profiles...")

        for x in policy_profiles:
            policy_graph.add_node(
                "A_"+x['@name'],
                name=x['@name'],
                type="auth_profile")

    except Exception as e:
        exc_type, exc_obj, exc_tb = sys.exc_info()
        fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
        print(f"Encountered exception : {e} {exc_type} {fname} {exc_tb.tb_lineno}")


def init_rules(policy_sets):
    global policy_graph

    try:
        for p in policy_sets:
            print(f"Populating graph with policy set {p.get('name')}...")

            # policy set node
            policy_graph.add_node(
                "P_"+p.get('name'),
                name=p.get('name'),
                type="policy")

            # adding edges for policy condition
            policy_graph.add_edges_from([("C_"+c, "P_"+p.get('name')) for c in flatten_references(p.get('condition'))])

            # creating nodes for rules
            for rule_type in ['authorRules', 'authenRules']:
                for r in listify(p.get(rule_type)):
                    r_node_name = "R_" + rule_type + '_' + p.get('name') + "_" + r.get('name')
                    if r_node_name not in policy_graph.nodes.keys():
                        policy_graph.add_node(
                            r_node_name,
                            name=r.get('name') if r.get('status') != "DISABLED" else "* "+r.get('name'),
                            type=rule_type,
                            status=r.get('status'))

                    # Add edge between policy and rules
                    policy_graph.add_edge(r_node_name, "P_"+p.get('name'))

                    if isinstance(r.get('condition'), dict):
                        # Add edge between conditions and rules
                        policy_graph.add_edges_from([("C_"+r, r_node_name) for r in flatten_references(r.get('condition', dict()).get('children', dict()))])

                    for a in listify(r.get('profiles')):
                        # Add edge between authorization profile and rules
                        policy_graph.add_edge("A_"+a, r_node_name)

    except Exception as e:
        exc_type, exc_obj, exc_tb = sys.exc_info()
        fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
        print(f"Encountered exception : {e} {exc_type} {fname} {exc_tb.tb_lineno}")


def populate_successors(start_element, src_graph, dest_graph):
    # get list of start element successors
    successors = list(src_graph.successors(start_element))

    dest_graph.add_nodes_from([x for x in src_graph.nodes.items() if x[0] in successors])
    dest_graph.add_edges_from([(y, start_element) for y in successors])

    for s in successors:
        populate_successors(s, src_graph, dest_graph)


def gen_perpolicy_graph():
    global policy_graph
    reversed_policy_graph = policy_graph.reverse()

    for p_node in [k for (k, v) in list(policy_graph.nodes(data=True)) if v.get('type') == "policy"]:
        # Create a graph per policy
        per_policy_graph = nx.DiGraph()
        # Add nodes for the current policy
        per_policy_graph.add_nodes_from([x for x in policy_graph.nodes.items() if x[0] == p_node])
        populate_successors(p_node, reversed_policy_graph, per_policy_graph)
        # Generate pyyed graph per policy
        to_pyyed(per_policy_graph, p_node)

    # Generate global policyset pyyed graph
    to_pyyed(policy_graph, "global")


def to_pyyed(graph, policy_name):
    try:
        pg = pyyed.Graph()

        for n in list(graph.nodes):
            geo = dict()
            if graph.nodes[n]['type'] == 'policy':
                width = str(len(graph.nodes[n]['name']) * 55)
                geo = {'font_size': '80', 'height': '120', 'shape_fill': '#FFFFFF', 'width': width}
            elif graph.nodes[n]['type'] == 'condition':
                geo = {'shape': 'diamond', 'height': '100', 'width': '100'}
                if graph.nodes[n]['name'] in cisco_default_conditions:
                    geo['shape_fill'] = '#ff9900'
                else:
                    geo['shape_fill'] = '#ff0000'
            elif graph.nodes[n]['type'] == 'authorRules':
                geo = {'shape': 'ellipse', 'height': '110', 'width': '110', 'shape_fill': '#99cc00'}
                if graph.nodes[n]['status'] == 'DISABLED':
                    geo['shape_fill'] = '#e0e6c3'
            elif graph.nodes[n]['type'] == 'authenRules':
                geo = {'shape': 'ellipse', 'height': '110', 'width': '110', 'shape_fill': '#99ccff'}
                if graph.nodes[n]['status'] == 'DISABLED':
                    geo['shape_fill'] = '#d3e0ed'
            elif graph.nodes[n]['type'] == 'auth_profile':
                geo = {'shape': 'star6', 'height': '90', 'width': '90'}
                if graph.nodes[n]['name'] in cisco_default_authprofiles:
                    geo['shape_fill'] = '#ff9900'
                else:
                    geo['shape_fill'] = '#ff0000'
            pg.add_node(n, label=graph.nodes[n]['name'], **geo)

        for e in list(graph.edges):
            geo = dict()
            if graph.nodes[e[0]]['type'] == 'condition' and graph.nodes[e[1]]['type'] == 'policy':
                geo['width'] = "10.0"
            pg.add_edge(e[0], e[1], arrowhead="standard", **geo)

        pg.write_graph(output_dir+'/'+policy_name+".graphml")
        print(f"Generated {output_dir}/{policy_name}.graphml")

    except Exception as e:
        exc_type, exc_obj, exc_tb = sys.exc_info()
        fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
        print(f"Encountered exception : {e} {exc_type} {fname} {exc_tb.tb_lineno}")


def policy_analyzer(json_policy):
    global policy_graph
    print(f"Analyzing policy file")

    policy_conditions = json_policy.get('libraryConditions')
    init_conditions(policy_conditions)

    policy_auth_profiles = json_policy.get('AznResults', dict()).get('StandardResults', dict()).get('Profile', dict())
    init_auth_profiles(policy_auth_profiles)

    radius_policy_sets = json_policy.get('policysets').get('radiusPolicySets', dict()).get('radiusPolicySet', list())
    init_rules(radius_policy_sets)

    gen_perpolicy_graph()


if __name__ == "__main__":
    main()