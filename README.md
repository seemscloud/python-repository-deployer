```python
# -*- coding: utf-8 -*-
 
import requests
import yaml
import os
import sys
import json
import string
import random
import logging
import argparse
import warnings
 
from Crypto.PublicKey import RSA
 
HOSTS_FILE = """
10.100.100.100\telastic\tpdc\tnode1\tElasticsearch\telasticsearch\tProduction\tproduction
10.100.100.101\telastic\tpdc\tnode2\tElasticsearch\telasticsearch\tProduction\tproduction
10.100.100.102\telastic\tpdc\tnode3\tElasticsearch\telasticsearch\tProduction\tproduction
10.100.100.103\telastic\tpdc\tnode4\tElasticsearch\telasticsearch\tProduction\tproduction
10.100.100.104\telastic\tpdc\tnode5\tElasticsearch\telasticsearch\tProduction\tproduction
10.100.100.105\telastic\tpdc\tnode6\tElasticsearch\telasticsearch\tProduction\tproduction
10.100.100.100\telastic\tpdc\tnode1\tElasticsearch\telasticsearch\tDisaster\tdisaster
10.100.100.101\telastic\tpdc\tnode2\tElasticsearch\telasticsearch\tDisaster\tdisaster
10.100.100.102\telastic\tpdc\tnode3\tElasticsearch\telasticsearch\tDisaster\tdisaster
10.100.100.103\telastic\tpdc\tnode4\tElasticsearch\telasticsearch\tDisaster\tdisaster
10.100.100.104\telastic\tpdc\tnode5\tElasticsearch\telasticsearch\tDisaster\tdisaster
10.100.100.105\telastic\tpdc\tnode6\tElasticsearch\telasticsearch\tDisaster\tdisaster
"""
 
CONFIG_FILE = """
host:
address: gitrep.localdomain
port: 443
protocol: https
 
api:
version: 4
token: XXXXXXXXXXXX
 
paggination:
per_page: 999999
"""
 
ADMINS_FILE = """
Jan Kowalsk\tjan.kowalski
"""
 
deploy_template = """
GITLAB_ADDR={gitlab_addr}
 
GITLAB_NAMESPACE={project_namespace}
GITLAB_PROJECT_NAME={project_name}
GITLAB_USERNAME={project_username}
GITLAB_EMAIL={project_name}@{gitlab_hostname}
 
RSA_PRIVATE_NAME={private_key_name}
RSA_PUBLIC_NAME={public_key_name}
 
cat > /root/repository.sh << 'EOF'
#!/bin/bash
 
ZBX_DIR=/opt/zabbix/agent
ZBX_SHARE_DIR=$ZBX_DIR/share
ZBX_REPO_DIR=$ZBX_SHARE_DIR/repository
 
REPO_DIR=/root/repository
REPO_FILE=$ZBX_REPO_DIR/repository.list
 
[ ! -d "$ZBX_DIR" ] && echo "Zabbix Directory Not Exists.." && exit
[ ! -d "$ZBX_SHARE_DIR" ] && echo "Zabbix Share Directory Not Exists.." && exit
[ ! -d "$ZBX_REPO_DIR" ] && echo "Zabbix Repository Directory Not Exists.." && exit
[ ! -d "$REPO_DIR" ] && echo "Output Directory Not Exists.." && exit
[ ! -f "$REPO_FILE" ] && echo "Input File Not Exists.." && exit
 
while read -r LINE ; do
CANON_PATH=`readlink -e "$LINE"`
 
if [ $? -eq 0 ] ; then
  echo "$CANON_PATH"
  find "$CANON_PATH" -mindepth 1 -maxdepth 1 -type f -exec cp --parents --verbose --force {{}} /root/repository/ \;
fi
done < "$REPO_FILE"
 
cd $REPO_DIR || exit
 
git add -A
 
GIT_COMMENT="`who -a``w -h -u`"
 
git commit -a -m "Repository" -m "$GIT_COMMENT"
 
ssh-agent bash -c "ssh-add ~/.ssh/repository_key ; git push origin -u master"
EOF
 
chmod 600 /root/.ssh/$RSA_PRIVATE_NAME
chmod 600 /root/.ssh/$RSA_PUBLIC_NAME
 
git config --global core.editor vi
git config --global http.sslVerify false
 
mkdir -p /root/repository
cd /root/repository
 
ssh-agent bash -c "ssh-add ~/.ssh/$RSA_PRIVATE_NAME ; git clone git@$GITLAB_ADDR:$GITLAB_NAMESPACE/$GITLAB_PROJECT_NAME.git ."
 
git config user.name "$GITLAB_USERNAME"
git config user.email "$GITLAB_EMAIL"
"""
 
warnings.filterwarnings("ignore", message="Unverified HTTPS request")
 
VISIBILITY = "private"
ADMIN_NAME = "Administrator"
ADMIN_USERNAME = "administrator"
GITLAB_ADDR = "10.10.10.10"
GITLAB_HOSTNAME = "gitrep.localdomain"
ADMIN_DOMAIN = "localdomain"
 
CONFIG = yaml.safe_load(CONFIG_FILE)
 
ROOT_PATH = os.path.dirname(os.path.abspath(__file__))
SSH_KEYS_PATH = ROOT_PATH + "/ssh_keys"
 
logging.basicConfig(stream=sys.stdout, level=logging.DEBUG, format="%(asctime)s %(levelname)s  %(message)s")
 
 
def random_string(_max_length=16):
    password_characters = string.ascii_letters + string.digits
    return "".join(random.choice(password_characters) for i in range(_max_length))
 
 
def request_handler(_response, _type, _url, _headers, _params):
    if _response.status_code < 200 or _response.status_code >= 300:
        logging.error("--------------------------------------------------")
        logging.error("| R E Q U E S T")
        logging.error("|-------------------------------------------------")
        logging.error("| URL\t\t{}".format(_url))
        logging.error("| TYPE\t\t{}".format(_type))
        logging.error("| HEADERS\t{}".format(_headers))
        logging.error("| PARAMS\t{}".format(json.dumps(_params, indent=4, sort_keys=True)))
        logging.error("|")
        logging.error("|-------------------------------------------------")
        logging.error("| R E S P O N S E")
        logging.error("|-------------------------------------------------")
        logging.error("| CODE\t{}".format(_response.status_code))
        logging.error("| RESPONSE\n{}".format(json.dumps(json.loads(_response.content), indent=4, sort_keys=True)))
        sys.exit(1)
 
 
def get_request(_url, _headers=None, _params=None):
    try:
        url = "{}{}".format(_url, "?page=1&per_page={}".format(CONFIG["paggination"]["per_page"]))
 
        response = requests.get(url=url, headers=_headers, params=_params, verify=False)
 
        response.encoding = "UTF-8"
    except Exception as e:
        sys.exit("Problem to send request, exception: {}".format(e))
 
    request_handler(response, "GET", url, _headers, _params)
    return response.text
 
 
def post_request(_url, _headers=None, _params=None):
    try:
        response = requests.post(url=_url, headers=_headers, params=_params, verify=False)
 
        response.encoding = "UTF-8"
    except Exception as e:
        sys.exit("Problem to send request, exception: {}".format(e))
 
    request_handler(response, "POST", _url, _headers, _params)
    return response.text
 
 
def delete_request(_url, _headers=None, _params=None):
    try:
        response = requests.delete(url=_url, headers=_headers, params=_params, verify=False)
 
        response.encoding = "UTF-8"
    except Exception as e:
        sys.exit("Problem to send request, exception: {}".format(e))
 
    request_handler(response, "DELETE", _url, _headers, _params)
    return response.text
 
 
class User:
    def __init__(self, _id, _name, _username, _email, _is_admin=None, _password=None):
        self.id = _id
        self.name = _name
        self.username = _username
        self.email = _email
        self.is_admin = _is_admin
        self.password = _password
 
 
class Member:
    def __init__(self, _id, _name, _username):
        self.id = _id
        self.name = _name
        self.username = _username
 
 
class Group:
    def __init__(self, _id, _name, _path, _visibility):
        self.id = _id
        self.name = _name
        self.path = _path
        self.visibility = _visibility
 
 
class Project:
    def __init__(self, _id, _name, _path, ):
        self.id = _id
        self.name = _name
        self.path = _path
 
 
class API:
    def __init__(self):
        self.addr = "{}://{}:{}/api/v{}".format(CONFIG["host"]["protocol"], CONFIG["host"]["address"],
                                                CONFIG["host"]["port"], CONFIG["api"]["version"])
 
        self.headers = {
            "PRIVATE-TOKEN": CONFIG["api"]["token"], "Content-Type": "application/json"
        }
 
    def get_users(self):
        url = "{}/{}".format(self.addr, "users")
 
        return json.loads((get_request(url, self.headers)))
 
    def create_user(self, _name, _username, _email, _password, _admin="false", _can_create_group="false"):
        url = "{}/{}".format(self.addr, "users")
 
        params = {
            "email": _email, "username": _username, "password": _password, "name": _name, "admin": _admin,
            "projects_limit": "0", "can_create_group": _can_create_group, "skip_confirmation": "true",
            "external": "false"
        }
 
        return json.loads(post_request(url, self.headers, params))
 
    def delete_user(self, _id):
        url = "{}/{}/{}".format(self.addr, "users", _id)
 
        if _id != 1:
            return delete_request(url, self.headers)
 
    def get_groups(self):
        url = "{}/{}".format(self.addr, "groups")
 
        return json.loads(get_request(url, self.headers))
 
    def get_subgroups(self, _id):
        url = "{}/{}/{}/{}".format(self.addr, "groups", _id, "subgroups")
 
        return json.loads(get_request(url, self.headers))
 
    def get_group_projects(self, _id):
        url = "{}/{}/{}/{}".format(self.addr, "groups", _id, "projects")
 
        return json.loads(get_request(url, self.headers))
 
    def create_group(self, _name, _path, _visibility, _parent_id=None):
        url = "{}/{}".format(self.addr, "groups")
 
        params = {
            "name": _name, "path": _path, "visibility": _visibility, "parent_id": _parent_id, "lfs_enabled": "true",
            "auto_devops_enabled": "false", "request_access_enabled": "false",
 
        }
 
        return json.loads(post_request(url, self.headers, params))
 
    def delete_group(self, _id):
        url = "{}/{}/{}".format(self.addr, "groups", _id)
 
        return delete_request(url, self.headers)
 
    def create_project(self, _name, _path, _visibility, _namespace_id):
        url = "{}/{}".format(self.addr, "projects")
 
        params = {
            "name": _name, "path": _path, "visibility": _visibility, "namespace_id": _namespace_id,
            "auto_devops_enabled": "false", "snippets_enabled": "false", "wiki_enabled": "false",
            "request_access_enabled": "false", "shared_runners_enabled": "false", "lfs_enabled": "true",
            "container_registry_enabled": "false", "jobs_enabled": "false", "merge_requests_enabled": "false",
            "public_jobs": "false", "remove_source_branch_after_merge": "false",
            "printing_merge_request_link_enabled": "false", "issues_enabled": "false", "initialize_with_readme": "true"
        }
 
        return json.loads(post_request(url, self.headers, params))
 
    def member_to_project(self, _id, _user_id, _access_level):
        url = "{}/{}/{}/{}".format(self.addr, "projects", _id, "members")
 
        params = {
            "user_id": _user_id, "access_level": _access_level
        }
 
        return post_request(url, self.headers, params)
 
    def member_to_group(self, _id, _user_id, _access_level):
        url = "{}/{}/{}/{}".format(self.addr, "groups", _id, "members")
 
        params = {
            "user_id": _user_id, "access_level": _access_level
        }
 
        return post_request(url, self.headers, params)
 
    def get_group_members(self, _id):
        url = "{}/{}/{}/{}".format(self.addr, "groups", _id, "members")
 
        return json.loads(get_request(url, self.headers))
 
    def get_project_members(self, _id):
        url = "{}/{}/{}/{}".format(self.addr, "projects", _id, "members")
 
        return get_request(url, self.headers)
 
    def delete_member_from_group(self, _id, _user_id):
        url = "{}/{}/{}/{}/{}".format(self.addr, "groups", _id, "members", _user_id)
 
        return delete_request(url, self.headers)
 
    def delete_member_from_project(self, _id, _user_id):
        url = "{}/{}/{}/{}/{}".format(self.addr, "projects", _id, "members", _user_id)
 
        return delete_request(url, self.headers)
 
    def add_user_ssh_key(self, _id, _title, _key):
        url = "{}/{}/{}/{}".format(self.addr, "users", _id, "keys")
 
        params = {
            "title": _title, "key": _key
        }
 
        return post_request(url, self.headers, params)
 
    def fetch_users(self):
        return [User(i["id"], i["name"], i["username"], i["email"], i["is_admin"]) for i in self.get_users()]
 
    def fetch_groups(self):
        return [Group(i["id"], i["name"], i["path"], i["visibility"]) for i in self.get_groups()]
 
    def fetch_group_members(self, _id):
        return [Member(i["id"], i["name"], i["username"]) for i in self.get_group_members(_id)]
 
    def fetch_subgroups(self, _id):
        return [Group(i["id"], i["name"], i["path"], i["visibility"]) for i in self.get_subgroups(_id)]
 
    def fetch_group_projects(self, _id):
        return [Project(i["id"], i["name"], i["path"]) for i in self.get_group_projects(_id)]
 
 
def ssh_bash_output(_path, _filename, _content, _mode, _ssh_path, _ssh_filename):
    f = open(_path + "/" + _filename, _mode)
    f.write("mkdir -p {}\n".format(_ssh_path).encode("utf-8"))
    f.write("\n".encode("utf-8"))
 
    f.write("cat > {}/{} << 'EOF'\n".format(_ssh_path, _ssh_filename).encode("utf-8"))
    f.write(_content + "\n".encode("utf-8"))
    f.write("EOF\n".encode("utf-8"))
    f.write("\n".encode("utf-8"))
 
    f.write("chmod 700 {}\n".format(_ssh_path).encode("utf-8"))
    f.write("chmod 600 {}/{}\n".format(_ssh_path, _ssh_filename).encode("utf-8"))
    f.close()
 
 
def confirm_prompt():
    answer = input("Are you sure? ")
 
    if answer.upper() in ["Y", "YES"]:
        pass
    elif answer.upper() in ["N", "NO"]:
        sys.exit("Bay bay")
    else:
        sys.exit("Choose y/yes or n/no")
 
 
def parse_users_file():
    users = []
 
    for line in ADMINS_FILE.split("\n"):
        if len(line.strip()) != 0:
            col = line.strip().split("\t")
            if len(col) == 2:
                users.append(User(None, col[0], col[1], "{}@{}".format(col[1], ADMIN_DOMAIN), None, random_string()))
 
    return users
 
 
def save_to_file(_dest, _filename, _content, _mode):
    f = open(_dest + "/" + _filename, _mode)
    f.write(_content + "\n")
    f.close()
 
 
def init_data(api):
    if not os.path.isdir(SSH_KEYS_PATH):
        os.mkdir(SSH_KEYS_PATH)
 
    for line in HOSTS_FILE.split("\n"):
        if len(line.strip()) != 0:
 
            col = line.strip().split("\t")
 
            if len(col) >= 6 and (len(col) % 2) == 0:
                name = "{}-{}-{}".format(col[1], col[2], col[3])
                email = "{}@{}".format(name, GITLAB_HOSTNAME)
 
                root_group = None
 
                for i in range(3, len(col) - 3 + 1, 2):
                    if i == 3:
                        for g in api.fetch_groups():
                            if g.name == col[i + 1] and g.path == col[i + 2]:
                                root_group = g
                                break
                        if root_group is None:
                            resp = api.create_group(col[i + 1], col[i + 2], VISIBILITY)
                            root_group = Group(resp["id"], resp["name"], resp["path"], resp["visibility"])
                    else:
                        tmp_id = root_group.id
                        root_group = None
 
                        for g in api.fetch_subgroups(tmp_id):
                            if g.name == col[i + 1] and g.path == col[i + 2]:
                                root_group = g
                                break
                        if root_group is None:
                            resp = api.create_group(col[i + 1], col[i + 2], VISIBILITY, tmp_id)
                            root_group = Group(resp["id"], resp["name"], resp["path"], resp["visibility"])
 
                exists = False
 
                for p in api.fetch_group_projects(root_group.id):
                    if p.name == name and p.path == name:
                        exists = True
 
                if not exists:
                    resp = api.create_project(name, name, VISIBILITY, root_group.id)
 
                    project_id = resp["id"]
                    project_namespace = resp["namespace"]["full_path"]
 
                    password = random_string(16)
                    resp = api.create_user(name, name, email, password)
                    user_id = resp["id"]
 
                    export_path = SSH_KEYS_PATH + "/{}".format(name)
                    os.mkdir(export_path)
 
                    rsa_key = RSA.generate(4096)
 
                    private_key = rsa_key.exportKey("PEM")
                    public_key = rsa_key.publickey().exportKey("OpenSSH")
 
                    private_key_name = "repository_key"
                    public_key_name = "{}.pub".format(private_key_name)
 
                    ssh_bash_output(export_path, "deploy.sh", private_key, "wb", "/root/.ssh", private_key_name)
                    ssh_bash_output(export_path, "deploy.sh", public_key, "ab", "/root/.ssh", public_key_name)
 
                    deploy_script = deploy_template.format(gitlab_addr=GITLAB_ADDR, gitlab_hostname=GITLAB_HOSTNAME,
                                                           project_namespace=project_namespace, project_name=name,
                                                           project_username=name, dest_addr=col[0],
                                                           private_key_name=private_key_name,
                                                           public_key_name=public_key_name)
 
                    save_to_file(export_path, "deploy.sh", deploy_script, "a")
 
                    api.add_user_ssh_key(user_id, name, public_key)
                    api.member_to_project(project_id, user_id, 40)
            else:
                logging.error("Fail when line parse. col={}, line={}".format(len(col), line))
                sys.exit(1)
 
 
def init_operators(api):
    for nu in parse_users_file():
        exists = False
 
        for u in api.fetch_users():
            if u.username == nu.username and u.email == nu.email:
                exists = True
 
        if not exists:
            print(nu.password)
            api.create_user(nu.name, nu.username, nu.email, nu.password, "true", "true")
 
 
def fix_operators(api):
    for nu in parse_users_file():
        for u in api.fetch_users():
            if u.username == nu.username and u.email == nu.email:
                for g in api.fetch_groups():
                    not_exists = True
                    for m in api.fetch_group_members(g.id):
                        if u.id == m.id:
                            not_exists = False
                            break
                    if not_exists:
                        api.member_to_group(g.id, u.id, 50)
 
 
def fix_admin(api):
    for g in api.fetch_groups():
        for m in api.fetch_group_members(g.id):
            if m.name == ADMIN_NAME and m.username == ADMIN_USERNAME:
                api.delete_member_from_group(g.id, m.id)
                break
 
 
def clean_all(api):
    for g in api.fetch_groups():
        api.delete_group(g.id)
 
    for u in api.fetch_users():
        api.delete_user(u.id)
 
 
def clean_command_handler(args):
    if args.target == "all":
        confirm_prompt()
        clean_all(API())
 
 
def init_command_handler(args):
    if args.target == "operators":
        init_operators(API())
    elif args.target == "data":
        init_data(API())
 
 
def fix_command_handler(args):
    if args.target == "admin":
        fix_admin(API())
    elif args.target == "operators":
        fix_operators(API())
 
 
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
 
    commands = parser.add_subparsers(dest="command")
 
    clean_parser = commands.add_parser("clean")
    clean_parser.add_argument("-t", "--target", choices=["all"], required=True)
 
    init_parser = commands.add_parser("init")
    init_parser.add_argument("-t", "--target", choices=["operators", "data"], required=True)
 
    fix_parser = commands.add_parser("fix")
    fix_parser.add_argument("-t", "--target", choices=["operators", "admin"], required=True)
 
    args = parser.parse_args()
 
    if args.command == "init":
        init_command_handler(args)
    elif args.command == "clean":
        clean_command_handler(args)
    elif args.command == "fix":
        fix_command_handler(args)
```
