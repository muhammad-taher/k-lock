#include "include/common.h"
#include <iostream>
#include <fstream>
#include <string>

using namespace std;

void start_monitor() {
    ifstream trace_pipe("/sys/kernel/debug/tracing/trace_pipe");
    string line;
    while (getline(trace_pipe, line)) {
        if (line.find("BLOCK") != string::npos) {
            cout << "[ALERT] " << line << endl;
        }
    }
}
