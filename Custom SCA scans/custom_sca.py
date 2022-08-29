#!/var/ossec/framework/python/bin/python3

import requests, urllib3
import sys
import json
import logging, os
import argparse
from socket import socket, AF_UNIX, SOCK_DGRAM

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
socketAddr = '/var/ossec/queue/sockets/queue'

# Send message to socket
def send_event(msg):
    logging.debug('Sending {} to {} socket.'.format(msg, socketAddr))
    string = '1:custom_sca_scan:{}'.format(msg)
    sock = socket(AF_UNIX, SOCK_DGRAM)
    sock.connect(socketAddr)
    sock.send(string.encode())
    sock.close()

# Configuring a logger for the script.
def set_logger(name, logfile=None):
    hostname = os.uname()[1]
    format = '%(asctime)s {0} {1}: [%(levelname)s] %(message)s'.format(hostname, name)
    logging.basicConfig(level=logging.INFO, format=format, datefmt="%Y-%m-%d %H:%M:%S", filename=logfile)
    if logfile:
        console = logging.StreamHandler()
        console.setLevel(logging.DEBUG)
        formatter = logging.Formatter(format, datefmt="%Y-%m-%d %H:%M:%S")
        console.setFormatter(formatter)
        logging.getLogger('').addHandler(console)

# Function to get the Wazuh API Token
def get_token(user="wazuh", passw="wazuh", ip='localhost', port='55000'):
    logging.info("Obtaining the Wazuh API token")
    hook_url = "https://"+ip+":"+port+"/security/user/authenticate?raw=true"
    try:
        response = requests.get(hook_url, auth=(user, passw), verify=False)
        return response.text
    except Exception as e:
        logging.error("Error getting the token. Details: "+str(e))
        sys.exit(1)

# Function to get the list of groups
def get_groups(token, ip='localhost', port='55000'):
    logging.info("Getting the list of groups")
    hook_url = "https://"+ip+":"+port+"/groups"
    try:
        response = requests.get(hook_url, headers={'Authorization': 'Bearer '+token}, verify=False)
        dict_out = json.loads(response.text)
        return dict_out
    except Exception as e:
        logging.error("Error getting the list of groups. Details: {}".format(str(e)))
        sys.exit(1)

# Function to get the Agents in a Group
def get_agents(token, grp_id, ip='localhost', port='55000'):
    logging.info("Getting the list of agents in the group: "+grp_id)
    hook_url = "https://"+ip+":"+port+"/groups/"+grp_id+"/agents"
    try:
        response = requests.get(hook_url, headers={'Authorization': 'Bearer '+token}, verify=False)
        dict_out = json.loads(response.text)
        return dict_out
    except Exception as e:
        logging.error("Error getting the list of agents for the group {}. Details: {}".format(grp_id,str(e)))
        sys.exit(1)

def get_sca(token, agt_id, ip='localhost',policyid='', port='55000'):
    logging.info("Getting the SCA results of policy "+policyid+" in agent "+agt_id)
    hook_url = "https://"+ip+":"+port+"/sca/"+agt_id+"/checks/"+policyid
    try:
        response = requests.get(hook_url, headers={'Authorization': 'Bearer '+token}, verify=False)
        dict_out = json.loads(response.text)
        return dict_out
    except Exception as e:
        logging.error("Error getting the sca results for the agent {}. Details: {}".format(agt_id,str(e)))
        sys.exit(1)


if __name__ == "__main__":
    set_logger("sca-alerts")
    # Parsing arguments
    parser = argparse.ArgumentParser(prog="sca-alerts.py", description='Get SCA information from agents and inject it in Wazuh as an alert.')
    parser.add_argument('--group',nargs='*', help='Group name to query. If not specified, the default group will be queried.')
    parser.add_argument('--user', help='User name of the environment')
    parser.add_argument('--passw', help='Password of the environment')
    parser.add_argument('--ip', help='IP address of the manager. If not specified, it will be localhost')
    parser.add_argument('--port', help="Port of the manager's API. If not specified, it will be 55000")
    parser.add_argument('--policyid', nargs='+', help='ID of the policies to monitor')
    args = parser.parse_args()
    if not (args.user and args.passw and args.policyid):
        parser.print_help(sys.stderr)
        sys.exit(1)
    ip='localhost'
    port='55000'
    if(args.ip):
        ip = args.ip
    if(args.port):
        port = args.port
    # Parsing the groups
    api_token = get_token(args.user, args.passw,ip, port)
    dict_grp = get_groups(api_token,ip, port)
    tmp_grp = []
    for item in dict_grp["data"]["affected_items"]:
        tmp_grp.append(item["name"])
    if not (args.group):
        groups = ['default']
    else:
        groups = args.group
        for item in groups:
            if item not in tmp_grp:
                logging.warning("This group does not exists ignoring: "+item)
                groups.remove(item)
    if len(groups) == 0:
        logging.error("No valid groups were passed. Please specify existent groups.")
        sys.exit(1)


    # Main Program
    logging.info("Working with the Inventory information")
    for group_name in groups:
        try:
            agents = get_agents(api_token, group_name,ip, port)
            for agent in agents["data"]["affected_items"]:
                for policy in args.policyid:
                    result = get_sca(api_token,agent["id"],ip,policy,port)
                    for itm in result["data"]["affected_items"]:
                        tmp = {
                            "custom_sca_scan":{}

                        }
                        tmp["custom_sca_scan"]["agent"]={
                            "id":agent["id"],
                            "name":agent["name"],
                            "ip":agent["ip"],
                        }

                        tmp["custom_sca_scan"]["sca"] = {
                            "result": itm["result"],
                            "remediation": itm["remediation"],
                            "description": itm["description"],
                            "id":itm["id"],
                            "title": itm["title"],
                            "rationale": itm["rationale"]
                        }
                        json_msg = json.dumps(tmp, default=str)
                        send_event(json_msg)
        except Exception as e:
            logging.error("Error! "+ str(e) + "at" + str(policy) + "for agent" + str(agent.id))
    logging.info("Finished getting the sca information for the group")