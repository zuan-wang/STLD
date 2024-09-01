#pragma once
#include <iostream>
#include <map>
#include <string>
#include <vector>
#include <array>
#include <queue>
#include <map>
#include <set>
#include <bitset>
#include <iostream>
#include <memory>
#include "rest_rpc.hpp"
#include <chrono>
#include <thread>
#include "ophelib/paillier_fast.h"
#include "ophelib/vector.h"
#include "ophelib/packing.h"
#include "ophelib/util.h"
#include "ophelib/ml.h"
#include "ophelib/random.h"
#include <cmath>
#include <sstream>
#include <mutex>
#include <atomic>
#include <chrono>
using std::string;
using std::vector;
using std::pair;
using std::array;
using std::shared_ptr;
using std::queue;
using std::priority_queue;
using std::map;
using std::set;
using std::bitset;
using namespace ophelib;
using namespace rest_rpc;
using namespace std::chrono;
using namespace rest_rpc::rpc_service;

namespace config{
    const string workspaceFolder = "/home/heres/STLD-CXX";
    const string logFolder = workspaceFolder + "/log"; // log folder
    const string dataFolder = workspaceFolder + "/data/ppnn"; // data folder
    const string keysFolder = workspaceFolder + "/keys"; // paillier folder
    const string resultFolder = workspaceFolder + "/res-new03"; // result folder
    const string queryFolder = workspaceFolder + "/query"; // query folder
    constexpr uint32_t KEY_SIZE = 1024; // paillier key size

    constexpr size_t FLOAT_EXP = 30; // float point accuracy (10^EXP times)
    constexpr size_t NUM_THREADS = 6; // parallel

    const string DO_IP = "127.0.0.1"; // ip of four entities
    const string DSP_IP = "127.0.0.1";
    const string DAP_IP = "127.0.0.1";
    const string CA_IP = "127.0.0.1";
    
    const int DO_PORT = 10011; // port of four entities
    const int DSP_PORT = 10012;
    const int DAP_PORT = 10013;
    const int CA_PORT = 10004;
};