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
#include <pwd.h>
#include <time.h>
#include "include/json.hpp"
#include "include/common.h"
#include <thread>
#include <chrono>
#include <filesystem>
#include <sys/stat.h>

using json = nlohmann::json;
using namespace std;

struct text_key_t {
    char name[32];
};

ofstream log_file;


string get_timestamp() {
    time_t now;
    time(&now);
    char buf[sizeof("2026-04-24T10:45:12Z")];
    strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", gmtime(&now));
    return string(buf);
}

json get_ancestry(int pid) {
    json ancestry = json::array();
    int current_pid = pid;

    for(int i = 0; i < 4 && current_pid > 0; i++) {
        string stat_path = "/proc/" + to_string(current_pid) + "/stat";
        ifstream stat_file(stat_path);
        if(!stat_file.is_open()) break;
        
        string stat_content;
        getline(stat_file, stat_content);

        size_t start = stat_content.find('(');
        size_t end = stat_content.find(')');
        if (start != string::npos && end != string::npos) {
            string name = stat_content.substr(start + 1, end - start - 1);
            ancestry.push_back({{"pid", current_pid}, {"name", name}});
            
            // PPID is the 4th field in /proc/[pid]/stat
            istringstream iss(stat_content.substr(end + 2));
            string state; int ppid;
            iss >> state >> ppid;
            current_pid = ppid;
        } else {
            break;
        }
    }
    return ancestry;
}

string get_cmdline(int pid) {
    string cmd_path = "/proc/" + to_string(pid) + "/cmdline";
    ifstream cmd_file(cmd_path);
    if (!cmd_file.is_open()) return "";
    
    string cmdline, arg;
    while (getline(cmd_file, arg, '\0')) {
        cmdline += arg + " ";
    }
    if (!cmdline.empty()) cmdline.pop_back(); 
    return cmdline;
}


int handle_event(void *ctx, void *data, size_t data_sz) {
    event_t *e = static_cast<event_t*>(data);
    json j;

    j["timestamp"] = get_timestamp();
    
    if (e->event_type == 0) j["event_type"] = "lsm/restrict_exec";
    else if (e->event_type == 1) j["event_type"] = "lsm/restrict_network";
    else if (e->event_type == 2) j["event_type"] = "lsm/restrict_file_open";

    j["action"] = (e->action == 0) ? "ALLOWED" : "BLOCKED";

    struct passwd *pw = getpwuid(e->uid);
    j["process_context"] = {
        {"pid", e->pid},
        {"uid", e->uid},
        {"user", pw ? pw->pw_name : "unknown"}
    };

    string cmdline = get_cmdline(e->pid);
    char cwd[256] = "unknown";
    string cwd_path = "/proc/" + to_string(e->pid) + "/cwd";
    ssize_t len = readlink(cwd_path.c_str(), cwd, sizeof(cwd)-1);
    if (len != -1) cwd[len] = '\0';

    j["execution_details"] = {
        {"binary_path", string(e->target_data)},
        {"command_line", cmdline.empty() ? string(e->target_data) : cmdline},
        {"working_directory", string(cwd)}
    };

    j["process_ancestry"] = get_ancestry(e->pid);


    j["network_state"] = {
        {"active_connections", "N/A"},
        {"listening_ports", json::array()}
    };

    log_file << j.dump(2) << endl << endl;
    log_file.flush();
    

    if (e->action == 1) { 
        cout << "[ALERT] Blocked " << j["event_type"] << " for " << string(e->target_data) << " (PID: " << e->pid << ")" << endl;
    }
    return 0;
}


void load_ebpf_maps(struct bpf_object *obj, const string& config_path, const string& main_bin) {

    ifstream config_file(config_path);
    if (!config_file.is_open()) return;
    json config;
    config_file >> config;
    
    int map_ips = bpf_object__find_map_fd_by_name(obj, "allowed_ips");
    int map_files = bpf_object__find_map_fd_by_name(obj, "blocked_files");
    int map_cmds = bpf_object__find_map_fd_by_name(obj, "allowed_commands");
    int allowed_write_fd = bpf_map__fd(bpf_object__find_map_by_name(obj, "allowed_write_files"));

    if (config.contains("policy")) {
        
      
        if (config["policy"].contains("allowed_outbound_ips") && map_ips >= 0) {
            unsigned int next_ip_key;
            while (bpf_map_get_next_key(map_ips, NULL, &next_ip_key) == 0) {
                bpf_map_delete_elem(map_ips, &next_ip_key);
            }
            
            for (const auto& ip : config["policy"]["allowed_outbound_ips"]) {
                string ip_str = ip;
                unsigned int ip_int = ip_to_int(ip_str);
                unsigned int val = 1;
                bpf_map_update_elem(map_ips, &ip_int, &val, BPF_ANY);
            }
        }
   
        if (config["policy"].contains("blocked_paths") && map_files >= 0) {
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
 
            for (int j = idx; j < 32; j++) {
                struct text_key_t empty_key = {};
                bpf_map_update_elem(map_files, &j, &empty_key, BPF_ANY);
            }
        }
        
  
        if (config["policy"].contains("allowed_commands") && map_cmds >= 0) {
            struct text_key_t next_cmd_key;
           
            while (bpf_map_get_next_key(map_cmds, NULL, &next_cmd_key) == 0) {
                bpf_map_delete_elem(map_cmds, &next_cmd_key);
            }

            for (const auto& cmd : config["policy"]["allowed_commands"]) {
                string cmd_str = cmd;
                struct text_key_t key = {};
                memset(&key, 0, sizeof(key));
                strncpy(key.name, cmd_str.c_str(), 31);
                unsigned int val = 1;
                bpf_map_update_elem(map_cmds, &key, &val, BPF_ANY);
            }
        }

        if (!main_bin.empty() && map_cmds >= 0) {
            char *dcy = strdup(main_bin.c_str());
            char *base = basename(dcy);
            struct text_key_t key = {};
            memset(&key, 0, sizeof(key));
            strncpy(key.name, base, 31);
            unsigned int val = 1;
            bpf_map_update_elem(map_cmds, &key, &val, BPF_ANY);
            free(dcy);
        }
        
        if (config["policy"].contains("allowed_write_files") && allowed_write_fd >= 0) {
            int i = 0;
            for (const auto& file : config["policy"]["allowed_write_files"]) {
                if (i >= 32) break; 
                struct text_key_t key = {};
                strncpy(key.name, string(file).c_str(), sizeof(key.name) - 1);
                bpf_map_update_elem(allowed_write_fd, &i, &key, BPF_ANY);
                i++;
            }
           
            for (int j = i; j < 32; j++) {
                struct text_key_t empty_key = {};
                bpf_map_update_elem(allowed_write_fd, &j, &empty_key, BPF_ANY);
            }
        }
        
        cout << "[*] Config Hot-Reloaded! Memory synced." << endl;
    }
}



void config_watcher_thread(struct bpf_object *obj, const string& config_path, const string& main_bin) {
    auto last_time = std::filesystem::last_write_time(config_path);

    while (true) {
        std::this_thread::sleep_for(std::chrono::seconds(2));
        try {
            auto current_time = std::filesystem::last_write_time(config_path);
            if (current_time != last_time) {
                last_time = current_time;
                cout << "\n[!] Config change detected! Hot reloading rules..." << endl;
                load_ebpf_maps(obj, config_path, main_bin); // এখানে main_bin পাস করা হলো
            }
        } catch (const std::exception& e) {}
    }
}



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
    bpf_program__attach(bpf_object__find_program_by_name(obj, "restrict_unlink"));  
    bpf_program__attach(bpf_object__find_program_by_name(obj, "restrict_inode_create"));

    int map_pids = bpf_object__find_map_fd_by_name(obj, "protected_pids");
    int map_ips = bpf_object__find_map_fd_by_name(obj, "allowed_ips");
    int map_files = bpf_object__find_map_fd_by_name(obj, "blocked_files");
    int map_cmds = bpf_object__find_map_fd_by_name(obj, "allowed_commands");



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
        
        log_file.open("syscalls.json.log", ios::trunc);
        if (!log_file.is_open()) {
            cerr << "Error: Could not open syscalls.json.log for writing." << endl;
        } else {
            cout << "[+] Protection Active. Logging all calls to syscalls.json.log..." << endl;
        }
        
        pid_t mon_pid = fork();
        if (mon_pid == 0) {
            
            int rb_fd = bpf_object__find_map_fd_by_name(obj, "events_ringbuf");
            if (rb_fd < 0) {
                cerr << "Error: Failed to find events_ringbuf map" << endl;
                exit(1);
            }
            struct ring_buffer *rb = ring_buffer__new(rb_fd, handle_event, NULL, NULL);
            if (!rb) {
                cerr << "Error: Failed to create ring buffer" << endl;
                exit(1);
            }

            string config_file_path = "config.json";
            string main_bin = args.empty() ? "" : args[0]; 

            
            load_ebpf_maps(obj, config_file_path, main_bin);

            std::thread watcher(config_watcher_thread, obj, config_file_path, main_bin);
            watcher.detach();

    cout << "[*] K-Lock is running with Hot-Reloading enabled! Press Ctrl+C to stop." << endl;
            
            
            while (true) {
                ring_buffer__poll(rb, 100); 
            }
            exit(0);
        }
        
        int status;
        waitpid(pid, &status, 0);
        kill(mon_pid, SIGTERM);
        cout << "\n[+] Application exited." << endl;
    }
    return 0;
}