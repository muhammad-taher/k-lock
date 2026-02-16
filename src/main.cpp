#include <iostream>
#include <unistd.h>
#include <vector>
#include <sstream>
#include <sys/wait.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <fstream>
#include <cstring>
#include <libgen.h>
#include "include/json.hpp"
#include "include/common.h"

using json = nlohmann::json;
using namespace std;

struct text_key_t {
    char name[32];
};

int main(int argc, char **argv) {
    ifstream f("config.json");
    if (!f.good()) {
        cerr << "Error: config.json not found." << endl;
        return 1;
    }
    json config = json::parse(f);
    string cmd_str = config["run_command"];
    
    vector<string> args;
    stringstream ss(cmd_str);
    string item;
    while (getline(ss, item, ' ')) args.push_back(item);
    
    vector<char*> c_args;
    for (const auto& arg : args) c_args.push_back((char*)arg.c_str());
    c_args.push_back(nullptr);

    struct bpf_object *obj = bpf_object__open_file("rce_core.o", NULL);
    if (libbpf_get_error(obj)) {
        cerr << "Error: Failed to open rce_core.o" << endl;
        return 1;
    }

    if (bpf_object__load(obj)) {
        cerr << "Error: Failed to load BPF into kernel" << endl;
        return 1;
    }

    bpf_program__attach(bpf_object__find_program_by_name(obj, "handle_fork"));
    bpf_program__attach(bpf_object__find_program_by_name(obj, "restrict_network"));
    bpf_program__attach(bpf_object__find_program_by_name(obj, "restrict_file_open"));
    bpf_program__attach(bpf_object__find_program_by_name(obj, "restrict_exec"));

    int map_pids = bpf_object__find_map_fd_by_name(obj, "protected_pids");
    int map_ips = bpf_object__find_map_fd_by_name(obj, "allowed_ips");
    int map_files = bpf_object__find_map_fd_by_name(obj, "blocked_files");
    int map_cmds = bpf_object__find_map_fd_by_name(obj, "allowed_commands");

    if (config.contains("policy")) {
        if (config["policy"].contains("allowed_outbound_ips")) {
            for (const auto& ip : config["policy"]["allowed_outbound_ips"]) {
                string ip_str = ip;
                unsigned int ip_int = ip_to_int(ip_str);
                unsigned int val = 1;
                bpf_map_update_elem(map_ips, &ip_int, &val, BPF_ANY);
            }
        }
        if (config["policy"].contains("blocked_paths")) {
            int idx = 0;
            for (const auto& path : config["policy"]["blocked_paths"]) {
                if (idx >= 32) break; 
                string path_str = path;
                struct text_key_t key = {};
                memset(&key, 0, sizeof(key));
                strncpy(key.name, path_str.c_str(), 31);
                bpf_map_update_elem(map_files, &idx, &key, BPF_ANY);
                idx++;
            }
        }
        if (config["policy"].contains("allowed_commands")) {
            for (const auto& cmd : config["policy"]["allowed_commands"]) {
                string cmd_str = cmd;
                struct text_key_t key = {};
                memset(&key, 0, sizeof(key));
                strncpy(key.name, cmd_str.c_str(), 31);
                unsigned int val = 1;
                bpf_map_update_elem(map_cmds, &key, &val, BPF_ANY);
            }
        }
        
        if (!args.empty()) {
            string main_bin = args[0];
            char *dcy = strdup(main_bin.c_str());
            char *base = basename(dcy);
            struct text_key_t key = {};
            memset(&key, 0, sizeof(key));
            strncpy(key.name, base, 31);
            unsigned int val = 1;
            bpf_map_update_elem(map_cmds, &key, &val, BPF_ANY);
            free(dcy);
        }
    }

    pid_t pid = fork();
    if (pid == 0) {
        usleep(200000);
        execvp(c_args[0], c_args.data());
        cerr << "Failed to execute command: " << cmd_str << endl;
        exit(1);
    } else {
        cout << "[+] Launched PID: " << pid << " (" << cmd_str << ")" << endl;
        unsigned int secure_flag = 1;
        unsigned int target_pid = pid;
        bpf_map_update_elem(map_pids, &target_pid, &secure_flag, BPF_ANY);
        cout << "[+] Protection Active. Monitoring..." << endl;
        pid_t mon_pid = fork();
        if (mon_pid == 0) {
            start_monitor();
            exit(0);
        }
        int status;
        waitpid(pid, &status, 0);
        kill(mon_pid, SIGTERM);
        cout << "\n[+] Application exited." << endl;
    }
    return 0;
}

