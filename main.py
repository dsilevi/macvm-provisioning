import yaml
import json
import sys
import subprocess
import os
import os.path
import glob
import time

# import requests
email_address = "dsilevi@example.com"


class Configuration:
    def __init__(self, conf_file):
        self.dict = None
        self.conf_file = conf_file + ".yaml"
        self.ansible_vault_encrypt_cmd = "ansible-vault encrypt --vault-password-file "
        self.module_list_filename = "ansible/modules_list"
        self.kubeadm_config = "helpers/confkubeadm.yaml"
        self.kubeadm_join = "kubeadm_join.sh"

    def load_conf(self):
        try:
            with open(self.conf_file, 'r') as f:
                self.dict = yaml.safe_load(f)
                f.close()
        except Exception as e:
            print(f"Can\'t load configuration from {self.conf_file} with Exception {e}")
            return False
        return True

    def write_ansible_conf(self):
        try:
            file1 = self.dict["configuration"]["ansibleInventory"]["filename"] + ".yaml"
            if os.path.exists(file1):
                file2 = self.dict["configuration"]["ansibleInventory"]["filename"] + ".bak"
                os.rename(file1, file2)
            with open(f'{self.dict["configuration"]["ansibleInventory"]["filename"]}.yaml', "w") as f:
                tmpf = {"k8smasters": {"hosts": {}}}
                for master_node in range(len(self.dict["configuration"]["k8sCluster"]["masters"])):
                    for node in self.dict["configuration"]["k8sCluster"]["nodes"]:
                        if self.dict["configuration"]["k8sCluster"]["masters"][master_node] == node["name"]:
                            tmpf["k8smasters"]["hosts"][node["name"]] = {"ansible_host": node["ipAddress"]}
                            break
                yaml.dump(tmpf, f)
                #
                tmpf = {"k8smasterInit": {"hosts": {}}}
                for master_node in range(len(self.dict["configuration"]["k8sCluster"]["masters"])):
                    for node in self.dict["configuration"]["k8sCluster"]["nodes"]:
                        if self.dict["configuration"]["k8sCluster"]["masters"][master_node] == node["name"]:
                            tmpf["k8smasterInit"]["hosts"][node["name"]] = {"ansible_host": node["ipAddress"]}
                            break
                    break
                yaml.dump(tmpf, f)
                #
                tmpf = {"k8sworkers": {"hosts": {}}}
                for node in self.dict["configuration"]["k8sCluster"]["nodes"]:
                    i = True
                    for master_node in range(len(self.dict["configuration"]["k8sCluster"]["masters"])):
                        if node["name"] == self.dict["configuration"]["k8sCluster"]["masters"][master_node]:
                            i = False
                            break
                    if i:
                        tmpf["k8sworkers"]["hosts"][node["name"]] = {"ansible_host": node["ipAddress"]}
                yaml.dump(tmpf, f)
                #
                tmpf = {"k8shosts": {"children": {"k8smasters": {}, "k8sworkers": {}},
                                     "vars": {"ansible_user": self.dict["configuration"]["ansibleUser"]["name"],
                                              "ansible_become_user": self.dict["configuration"]["ansibleBecomeUser"][
                                                  "name"]}}}
                yaml.dump(tmpf, f)
                #
                f.close()
        except Exception as e:
            print(
                f'Can\'t write ansible configuration to {self.dict["configuration"]["ansibleInventory"]["filename"]}.yaml with Exception {e}')
            return False
        #
        if not os.path.exists(self.dict["configuration"]["ansibleVaultPasswd"]["filename"]):
            pwd = input("Please enter ansible vault password:")
            try:
                with open(self.dict["configuration"]["ansibleVaultPasswd"]["filename"], "w") as f:
                    f.write(pwd)
                f.close()
            except Exception as e:
                print(
                    f'Can\'t write ansible vault password to {self.dict["configuration"]["ansibleVaultPasswd"]["filename"]} with Exception {e}')
                return False
        #
        file1 = self.dict["configuration"]["ansibleVaultVars"]["filename"]
        if os.path.exists(file1):
            file2 = self.dict["configuration"]["ansibleVaultVars"]["filename"] + ".bak"
            try:
                os.rename(file1, file2)
            except Exception as e:
                print(f'Can\'t rename file {self.dict["configuration"]["ansibleVaultVars"]["filename"]}')
        if not os.path.exists(self.dict["configuration"]["ansibleVaultVars"]["filename"]):
            try:
                with open(self.dict["configuration"]["ansibleVaultPasswd"]["filename"], "r") as pwd_file:
                    pwd = pwd_file.read()
                pwd_file.close()
                with open(self.dict["configuration"]["ansibleVaultVars"]["filename"], "w") as vars_file:
                    vars_file.write(f'ansible_become_password: {pwd}\nansible_sudo_pass: {pwd}\n')
            except Exception as e:
                print(
                    f'Can\'t create vault-vars file {self.dict["configuration"]["ansibleVaultVars"]["filename"]} with Exception {e}')
                return False
            result = subprocess.run(
                self.ansible_vault_encrypt_cmd + self.dict["configuration"]["ansibleVaultPasswd"]["filename"] + " " +
                self.dict["configuration"]["ansibleVaultVars"]["filename"], shell=True, text=True, capture_output=True)
            if result.returncode != 0:
                print(f'Can\'t encrypt self.dict["configuration"]["ansibleVaultVars"]["filename"] with vault')
                return False
        return True

    def write_modules_list(self):
        if os.path.exists(self.module_list_filename):
            file2 = self.module_list_filename + ".bak"
            try:
                os.rename(self.module_list_filename, file2)
            except Exception as e:
                print(f'Can\'t rename file {self.module_list_filename} with Exception {e}')
        try:
            with open(self.module_list_filename, "w") as f:
                tmpf = {"commonPackagesWithVersions": self.dict["configuration"]["commonPackagesWithVersions"]}
                yaml.dump(tmpf, f)
                tmpf = {"commonPackagesLatest": self.dict["configuration"]["commonPackagesLatest"]}
                yaml.dump(tmpf, f)
                tmpf = {"helmRepositories": self.dict["configuration"]["helmRepositories"]}
                yaml.dump(tmpf, f)
                tmpf = {"kubernetesVersion": self.dict["configuration"]["kubernetesVersion"]}
                yaml.dump(tmpf, f)
                tmpf = {"kubernetesToolsVersion": self.dict["configuration"]["kubernetesToolsVersion"]}
                yaml.dump(tmpf, f)
                tmpf = {"pod_network_cidr": self.dict["configuration"]["pod_network_cidr"]}
                yaml.dump(tmpf, f)
                tmpf = {"service_cidr": self.dict["configuration"]["service_cidr"]}
                yaml.dump(tmpf, f)
                tmpf = {"cluster_domain": self.dict["configuration"]["cluster_domain"]}
                yaml.dump(tmpf, f)
                tmpf = {"helm_version": self.dict["configuration"]["helm_version"]}
                yaml.dump(tmpf, f)
                tmpf = {"calicoReleases": self.dict["configuration"]["calicoReleases"]}
                yaml.dump(tmpf, f)
        except Exception as e:
            print(f'Can\'t write modules list to {self.module_list_filename} with Exception {e}')
            return False
        return True

    def write_kubeadm_config(self):
        try:
            with open(self.kubeadm_config, "w") as f:
                tmpf = {"kubeAdmConfig": {"InitConfiguration": {}, "ClusterConfiguration": {}, "KubeProxyConfiguration": {}}}
                tmpf["kubeAdmConfig"]["InitConfiguration"] = {"apiVersion": "kubeadm.k8s.io/v1beta3"}
                tmpf["kubeAdmConfig"]["InitConfiguration"]["kind"] = "InitConfiguration"
                tmpf["kubeAdmConfig"]["InitConfiguration"]["localAPIEndpoint"] = {}
                tmpf["kubeAdmConfig"]["InitConfiguration"]["localAPIEndpoint"] = \
                    {"advertiseAddress": "0.0.0.0", "bindPort": 6443}
                tmpf["kubeAdmConfig"]["ClusterConfiguration"] = {"apiVersion": "kubeadm.k8s.io/v1beta3"}
                tmpf["kubeAdmConfig"]["ClusterConfiguration"]["kind"] = "ClusterConfiguration"
                tmpf["kubeAdmConfig"]["ClusterConfiguration"]["networking"] = {}
                tmpf["kubeAdmConfig"]["ClusterConfiguration"]["networking"] = \
                    {"serviceSubnet": self.dict["configuration"]["service_cidr"],
                     "podSubnet": self.dict["configuration"]["pod_network_cidr"],
                     "dnsDomain": self.dict["configuration"]["cluster_domain"]}
                tmpf["kubeAdmConfig"]["KubeProxyConfiguration"] = {"apiVersion": "kubeproxy.config.k8s.io/v1alpha1"}
                tmpf["kubeAdmConfig"]["KubeProxyConfiguration"]["kind"] = "KubeProxyConfiguration"
                tmpf["kubeAdmConfig"]["KubeProxyConfiguration"]["mode"] = "iptables"
                yaml.dump(tmpf["kubeAdmConfig"]["InitConfiguration"], f)
                f.write("---\n")
                yaml.dump(tmpf["kubeAdmConfig"]["ClusterConfiguration"], f)
                f.write("---\n")
                yaml.dump(tmpf["kubeAdmConfig"]["KubeProxyConfiguration"], f)
            f.close()
        except Exception as e:
            print(f'Can\'t create kubeadm configuration yaml {e}')
            return False
        return True


def ssh_keygen():
    global email_address
    tmpf = os.path.expanduser("~")
    if not (os.path.exists(os.path.join(tmpf, ".ssh/id_rsa")) and os.path.exists(
            os.path.join(tmpf, ".ssh/id_rsa.pub"))):
        print(f'SSH key-pair was not fount. Generating key-pair with no password and email {email_address}')
        print(f'No ssh key-pair found, trying to generate. email-address {email_address}')
        result = subprocess.run(f'ssh-keygen -t rsa -b 4096 -f ~/.ssh/id_rsa -N "" -C {email_address}', shell=True,
                                text=True, capture_output=True)
        if result.returncode != 0:
            print(f'Can\'t generate ssh key-pair')
            return False
    return True


def check_ssh(conf):
    check_prefix = "ssh -o StrictHostKeyChecking=no -o PasswordAuthentication=no -l "
    check_cmd = " \"ls -1d /tmp > /dev/null\""
    ssh_cp_cmd = f'sshpass -f {conf.dict["configuration"]["ansibleVaultPasswd"]["filename"]} ssh-copy-id '
    for node in conf.dict["configuration"]["k8sCluster"]["nodes"]:
        result = subprocess.run(
            check_prefix + conf.dict["configuration"]["ansibleUser"]["name"] + " " + node["ipAddress"] + check_cmd,
            shell=True, text=True, capture_output=True)
        if result.returncode != 0:
            print(f'Coping ssh ID to {node["name"]} with user {conf.dict["configuration"]["ansibleUser"]["name"]}')
            ssh_result = subprocess.run(
                f'{ssh_cp_cmd} {conf.dict["configuration"]["ansibleUser"]["name"]}@{node["ipAddress"]}', shell=True,
                text=True, capture_output=True)
            if ssh_result.returncode != 0:
                print(f'Can\'t copy ssh ID to {node["name"]}')
                return False
    return True


def load_ansible_modules(conf):
    for module in conf.dict["configuration"]["ansibleModules"]:
        result = subprocess.run(f'ansible-galaxy collection install {module}', shell=True, text=True,
                                capture_output=True)
        if result.returncode != 0:
            print(f'Can\'t install module {module}')
            return False
    return True


def write_workers_join_cmd(conf):
    directory = ""
    filename = ""
    cmd_lines = ["", ""]
    try:
        directory = os.path.dirname(conf.dict["configuration"]["ansibleInventory"]["filename"])
        entries = glob.glob(f'{directory}/kubeadm*')
        entries.sort(key=lambda f: os.path.getmtime(f), reverse=True)
        filename = f'{entries[0]}/kubeadm.out'
        print(f'filename = {filename} attributes = {time.ctime(os.path.getmtime(filename))}, {os.path.getsize(filename)} bytes')
        with open(filename, "r") as f:
            lines = [line for line in f]
        f.close()
        flag = 0
        for line in lines:
            if flag == 1:
                cmd_lines[1] = line
                break
            if line[:12] == "kubeadm join":
                cmd_lines[0] = line
                flag = 1
        print(cmd_lines)
        with open(f'{os.path.dirname(conf.kubeadm_config)}/{conf.kubeadm_join}', "w") as f:
            for line in cmd_lines:
                f.write(line)
        f.close()
    except Exception as e:
        print(f'Can\'t get kubeadm.out in {directory} with Exception {e}')
        return False
    return True


if __name__ == '__main__':
    if not len(sys.argv) == 2:
        print(f'Wrong number of arguments {sys.argv}')
        exit(1)
    #
    #
    configuration = Configuration(sys.argv[1])
    if not configuration.load_conf():
        print("Configuration init wasn\'t successful, exiting")
        exit(1)
    print(f'Loaded configuration: \n{yaml.dump(configuration.dict["configuration"], sort_keys=False)}')
    #
    if not configuration.write_ansible_conf():
        print("Couldn\'t write Ansible configuration")
        exit(1)
    print("Ansible configuration has been written")
    #
    #
    if not ssh_keygen():
        print("Can\'t initialize SSH key-pair")
        exit(1)
    print("SSH key-pair exist")
    #
    if not check_ssh(configuration):
        print("Can\'t initialize k8shosts with SSH")
        exit(1)
    print("K8S hosts were initialized with SSH")
    #
    #
    if not load_ansible_modules(configuration):
        print("Can\'t install ansible nodules")
        exit(1)
    print("Ansible modules were successfully installed")
    #
    #
    if not configuration.write_modules_list():
        print("Couldn\'t write list of modules")
        exit(1)
    #
    #
    if not configuration.write_kubeadm_config():
        print("Couldn\'t create kubeadm configuration yaml")
        exit(1)
    #
    #
    ansible_run = "ansible-playbook -i " + configuration.dict["configuration"]["ansibleInventory"]["filename"] + \
                  ".yaml k8shosts.yaml --vault-password-file " + \
                  configuration.dict["configuration"]["ansibleVaultPasswd"]["filename"] + \
                  " --extra-vars '{\"passwd_file\": \"" + configuration.dict["configuration"]["ansibleVaultVars"][
                      "filename"] + \
                  "\", \"modules_list\": \"" + configuration.module_list_filename + "\"}' --become-user " + \
                  configuration.dict["configuration"]["ansibleBecomeUser"]["name"] + " -b"
    print(f'We go with \n{ansible_run}')
    result = subprocess.run(ansible_run, shell=True, text=True, capture_output=False)
    if result.returncode != 0:
        print(f'Can\'t execute hosts bootstrap with ansible \n{result.stderr}')
        exit(1)
    #
    #
    ansible_run = "ansible-playbook -i " + configuration.dict["configuration"]["ansibleInventory"]["filename"] + \
                  ".yaml k8sinit.yaml --vault-password-file " + \
                  configuration.dict["configuration"]["ansibleVaultPasswd"]["filename"] + \
                  " --extra-vars '{\"passwd_file\": \"" + configuration.dict["configuration"]["ansibleVaultVars"][
                      "filename"] + \
                  "\", \"modules_list\": \"" + configuration.module_list_filename + "\"}' --become-user " + \
                  configuration.dict["configuration"]["ansibleBecomeUser"]["name"] + " -b"
    print(f'We go with \n{ansible_run}')
    result = subprocess.run(ansible_run, shell=True, text=True, capture_output=False)
    if result.returncode != 0:
        print(f'Can\'t execute hosts bootstrap with ansible \n{result.stderr}')
        exit(1)
    #
    #
    if not write_workers_join_cmd(configuration):
        print("Couldn\'t create join string for workers nodes")
        exit(1)
    #
    #
    ansible_run = "ansible-playbook -i " + configuration.dict["configuration"]["ansibleInventory"]["filename"] + \
                  ".yaml k8sjoinworkers.yaml --vault-password-file " + \
                  configuration.dict["configuration"]["ansibleVaultPasswd"]["filename"] + \
                  " --extra-vars '{\"passwd_file\": \"" + configuration.dict["configuration"]["ansibleVaultVars"][
                      "filename"] + \
                  "\", \"modules_list\": \"" + configuration.module_list_filename + "\"}' --become-user " + \
                  configuration.dict["configuration"]["ansibleBecomeUser"]["name"] + " -b"
    print(f'We go with \n{ansible_run}')
    result = subprocess.run(ansible_run, shell=True, text=True, capture_output=False)
    if result.returncode != 0:
        print(f'Can\'t join workers to the cluster \n{result.stderr}')
        exit(1)
