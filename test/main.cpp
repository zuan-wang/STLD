#include "config.hpp"
#include "entity.h"
#include "utility.h"
#include <NTL/tools.h>
#include <cstdio>
#include <fstream>
#include <string>

#include <filesystem>
#include <vector>

namespace fs = std::filesystem;


extern map<ERTreeEntry*, string> entryInfos;
extern TimerClock tc;
extern vector<double> costTimes;
extern vector<double> updateTimes;
extern vector<double> SLBCTimes;
extern vector<double> SBCTimes;
extern vector<double> SMETimes;
extern vector<double> SCGTimes;
extern double clearTime;

// string dataFolder_w ="";

std::vector<std::string> get_files_in_directory(const fs::path& directory) {
    std::vector<std::string> files;
    if (fs::exists(directory) && fs::is_directory(directory)) {
        for (const auto& entry : fs::directory_iterator(directory)) {
            if (fs::is_regular_file(entry.status())) {
                files.push_back(entry.path().filename().string());
            }
        }
    } else {
        std::cerr << "Directory does not exist or is not a directory: " << directory << std::endl;
    }
    return files;
}

void test_buildRTree()
{
    PaillierFast crypto(1024);
    crypto.generate_keys();
    RTree t = deSeriRTree(config::dataFolder + "/" + "test_2_12_rtree.txt");
    shared_ptr<ERTreeEntry> root = encryptRTree(crypto, t);

    std::function<void(shared_ptr<ERTreeEntry>)> fn = [](shared_ptr<ERTreeEntry> entry){
        std::cout << entryInfos[entry.get()] << std::endl;
    };
    traverseERTree(root, fn);

    count(root, crypto);
}

void test_SIC()
{
    DSP server;
    assert(server.SIC(server.crypto->encrypt(1746), server.crypto->encrypt(113)).data == 0);  // 0
    assert(server.SIC(server.crypto->encrypt(1), server.crypto->encrypt(2)).data == 1); // 1
    assert(server.SIC(server.crypto->encrypt(2), server.crypto->encrypt(1)).data == 0);  // 0
    assert(server.SIC(server.crypto->encrypt(0), server.crypto->encrypt(0)).data == 1);  // 1
    assert(server.SIC(server.crypto->encrypt(1), server.crypto->encrypt(1000000)).data == 1);  // 1
    assert(server.SIC(server.crypto->encrypt(1000000), server.crypto->encrypt(1)).data == 0);  // 0
}

void test_SVC()
{
    DSP server;
    {
        Vec<Ciphertext> vec_a(NTL::INIT_SIZE_TYPE{}, 3, server.crypto->encrypt(1));
        Vec<Ciphertext> vec_b(NTL::INIT_SIZE_TYPE{}, 3, server.crypto->encrypt(1));
        string res = server.SVC(vec_a, vec_b, USE_PLAINTEXT)[0].data.data.get_str();
        assert(res[res.size() - 1] - 1 == '1');
        assert(res[res.size() - 2] - 1 == '1');
        assert(res[res.size() - 3] - 1 == '1');
    }
    {
        Vec<Ciphertext> vec_a(NTL::INIT_SIZE_TYPE{}, 3);
        Vec<Ciphertext> vec_b(NTL::INIT_SIZE_TYPE{}, 3);
        vec_a[0] = server.crypto->encrypt(2);
        vec_a[1] = server.crypto->encrypt(3);
        vec_a[2] = server.crypto->encrypt(4); 
        vec_b[0] = server.crypto->encrypt(3); 
        vec_b[1] = server.crypto->encrypt(1); 
        vec_b[2] = server.crypto->encrypt(2);
        string res = server.SVC(vec_a, vec_b, USE_PLAINTEXT)[0].data.data.get_str();
        assert(res[res.size() - 1] - 1 == '1');
        assert(res[res.size() - 2] - 1 == '0');
        assert(res[res.size() - 3] - 1 == '0');
    }
    {
        Vec<Ciphertext> vec_a(NTL::INIT_SIZE_TYPE{}, 32, server.crypto->encrypt(2));
        Vec<Ciphertext> vec_b(NTL::INIT_SIZE_TYPE{}, 32, server.crypto->encrypt(1));
        auto res = server.SVC(vec_a, vec_b, USE_PLAINTEXT);
        for(size_t i = 0; i < res.size() - 1; ++i){
            string str = res[i].data.data.get_str();
            for(char& c: str){
                assert(c - 1 == '0');
            }
        }
        size_t rest = size_t(vec_a.length()) % Vector::pack_count(32, *(server.crypto));
        string str = res.back().data.data.get_str();
        for(size_t j = 0; j < rest; ++j){
            assert(str[str.size() - 1 - j] - 1 == '0');
        }
    }
}

void test_SDDC()
{
    DSP server;
    {

    }
}

void test_getDistance()
{
    DSP server;
    EncRectType encRect(2, EncPointType(2));
    encRect[LEFT_BOTTOM_CORNER][0] = server.crypto->encrypt(1);
    encRect[LEFT_BOTTOM_CORNER][1] = server.crypto->encrypt(11);
    encRect[RIGHT_UP_CORNER][0] = server.crypto->encrypt(56);
    encRect[RIGHT_UP_CORNER][1] = server.crypto->encrypt(43);
    // min distance
    assert(server.crypto->decrypt(server.getMinDistance(encRect, EncPointType{server.crypto->encrypt(0), server.crypto->encrypt(44)})) == 2);
    assert(server.crypto->decrypt(server.getMinDistance(encRect, EncPointType{server.crypto->encrypt(1), server.crypto->encrypt(43)})) == 0);
    assert(server.crypto->decrypt(server.getMinDistance(encRect, EncPointType{server.crypto->encrypt(28), server.crypto->encrypt(44)})) == 1);
    assert(server.crypto->decrypt(server.getMinDistance(encRect, EncPointType{server.crypto->encrypt(29), server.crypto->encrypt(43)})) == 0);
    assert(server.crypto->decrypt(server.getMinDistance(encRect, EncPointType{server.crypto->encrypt(57), server.crypto->encrypt(44)})) == 2);
    assert(server.crypto->decrypt(server.getMinDistance(encRect, EncPointType{server.crypto->encrypt(56), server.crypto->encrypt(43)})) == 0);
    assert(server.crypto->decrypt(server.getMinDistance(encRect, EncPointType{server.crypto->encrypt(57), server.crypto->encrypt(42)})) == 1);
    assert(server.crypto->decrypt(server.getMinDistance(encRect, EncPointType{server.crypto->encrypt(57), server.crypto->encrypt(10)})) == 2);
    assert(server.crypto->decrypt(server.getMinDistance(encRect, EncPointType{server.crypto->encrypt(28), server.crypto->encrypt(10)})) == 1);
    assert(server.crypto->decrypt(server.getMinDistance(encRect, EncPointType{server.crypto->encrypt(0), server.crypto->encrypt(0)})) == 1 + 11*11);
    assert(server.crypto->decrypt(server.getMinDistance(encRect, EncPointType{server.crypto->encrypt(0), server.crypto->encrypt(12)})) == 1);
    // max distance
    assert(server.crypto->decrypt(server.getMaxDistance(encRect, EncPointType{server.crypto->encrypt(28), server.crypto->encrypt(27)}, EncPointType{server.crypto->encrypt(0), server.crypto->encrypt(44)})) == 56*56 + 33*33);
    assert(server.crypto->decrypt(server.getMaxDistance(encRect, EncPointType{server.crypto->encrypt(28), server.crypto->encrypt(27)}, EncPointType{server.crypto->encrypt(0), server.crypto->encrypt(0)})) == 56*56 + 43*43);
    assert(server.crypto->decrypt(server.getMaxDistance(encRect, EncPointType{server.crypto->encrypt(28), server.crypto->encrypt(27)}, EncPointType{server.crypto->encrypt(57), server.crypto->encrypt(44)})) == 56*56 + 33*33);
    assert(server.crypto->decrypt(server.getMaxDistance(encRect, EncPointType{server.crypto->encrypt(28), server.crypto->encrypt(27)}, EncPointType{server.crypto->encrypt(57), server.crypto->encrypt(10)})) == 56*56 + 33*33);
}

void printResult(const vector<pair<vector<uint32_t>, int>>& W)
{
    for(auto& item: W){
        // string fmt = "point:[%s], score:%s";
        string fmt = format("point:[%s], score:%lu", point2str(item.first).c_str(), item.second);
        printf("%s\n", fmt.c_str());
    }
}

void test_STLD()
{
    DSP server;
    TimerClock tc;
    tc.update();
    server.loadRTree(config::dataFolder + "/" + "test_2_12_rtree.txt");
    EncPointType q(2);
    q[0] = server.crypto->encrypt(17);
    q[1] = server.crypto->encrypt(28);
    int k = 4;
    tc.update();
    auto W = server.topKQuery(q, k);
    printResult(W);
}

struct Param
{
    size_t n = 1000; // dataset size
    size_t d = 2; // total dim
    int k = 3; // top-k
    int capacity = 5;
    bool opt = false; // use optimize
    string indexFileName = "";
    string queryFileName = ""; // queries
};

struct Result
{
    double indexBuildTime = 0; // ms
    size_t indexSize = 0; // byte
    double avgQueryTime = 0; // average query time
};

size_t accIndexMemSize(shared_ptr<ERTreeEntry> root)
{
    size_t mem = 0;
    std::function<void (shared_ptr<ERTreeEntry>)> fn = [&mem](shared_ptr<ERTreeEntry> root){
        mem += sizeof(root->level_);
        mem += root->count_.size_bits() / 8;
        for(size_t i = 0; i < root->data_.size(); ++i) mem += root->data_[i].data.size_bits() / 8;
        mem += root->entries_.size() * sizeof(root);
        mem += sizeof(root->is_leaf_);
        for(size_t i = 0; i < root->rect_.size(); ++i){
            for(size_t j = 0; j < root->rect_[i].size(); ++j){
                mem += root->rect_[i][j].data.size_bits() / 8;
            }
        }
    };
    traverseERTree(root, fn);
    return mem;
}

void experiment(Param param)
{
    Result result;
    DSP server;
    TimerClock tc;

    // index build
    tc.update();
    std::cout << "当前密钥大小为："<<config::KEY_SIZE<< std::endl;
    std::cout << "载入"<<param.indexFileName<<"的数据..." << std::endl;
    server.loadRTree(config::dataFolder + "/" + param.indexFileName);
    result.indexBuildTime = tc.getTimerMilliSec();
    result.indexSize = accIndexMemSize(server.root_);
    std::cout << "载入"<<param.indexFileName<<"的数据成功！！！" << std::endl;

    // goto printlab;

    // query
     if(!param.queryFileName.empty())
    {   
        vector<vector<uint32_t>> queries = readQueryFromTxt(config::queryFolder + "/" + param.queryFileName, ' ');
        size_t n_query = queries.size();
        double queryTime = 0;
        for(size_t i = 0; i < n_query; ++i){
            EncPointType q(2);
            q[0] = server.crypto->encrypt(queries[i][0]);
            q[1] = server.crypto->encrypt(queries[i][1]);
            tc.update();
            auto W = server.topKQuery(q, param.k, param.opt);
            queryTime += tc.getTimerMilliSec();
            printResult(W);
        }
        result.avgQueryTime = queryTime / n_query;
    }

    // printlab:
    // result output
    string resultFileName = format("%s#%s#%s.txt", param.indexFileName.c_str(), param.queryFileName.c_str(), param.opt == true ? "opt" : "nopt");
    std::ofstream out(config::resultFolder + "/" + resultFileName);
    out << format("index build time:%.3f ms\nindex size:%lu B\navg query time:%.3f ms", result.indexBuildTime, result.indexSize, result.avgQueryTime);
}

void test_bitset()
{
    bitset<64> bs(1);
    assert(bs[0] == 1);
    assert(bs[63] == 0);
}

// 提取文件名中最后一个下划线和文件扩展名之间的数字
int extractNumberFromFilename(const std::string& filename) {
    size_t dotPos = filename.rfind('.'); // 找到文件扩展名的起始位置
    if (dotPos == std::string::npos) {
        std::cerr << "文件名中没有找到点（.）。" << std::endl;
        return -1;
    }

    size_t underscorePos = filename.rfind('_', dotPos); // 找到最后一个下划线的位置
    if (underscorePos == std::string::npos) {
        std::cerr << "文件名中没有找到下划线。" << std::endl;
        return -1;
    }

    std::string numberStr = filename.substr(underscorePos + 1, dotPos - underscorePos - 1); // 提取数字字符串

    try {
        int number = std::stoi(numberStr); // 将字符串转换为整数
        return number;
    } catch (const std::invalid_argument& ia) {
        std::cerr << "转换错误: " << ia.what() << std::endl;
    } catch (const std::out_of_range& oor) {
        std::cerr << "范围错误: " << oor.what() << std::endl;
    }
    return -1; // 如果转换失败，返回-1
}

void run(int argc, char* argv[])
{
    if(string(argv[1]) == "ca")
    {
        CA ca(config::keysFolder + "/" + string(argv[2]) + "-bit");
        ca.run();
    }
    else
    {
        Param param;
        // dataFolder_w = config::dataFolder+argv[1];
        // std::vector<std::string> files = get_files_in_directory( dataFolder_w);

        // for (const auto& file : files) {
        // // std::cout << file << std::endl;
        //     // param.indexFileName =argv[1];
        //     param.indexFileName = file; // "anti_2_3000_rtree_5.txt"

        //     param.queryFileName = argv[2]; // "query_anti_3.txt"
        //     param.k = param.queryFileName[param.queryFileName.size() - 5] - '0';
        //     param.opt = argv[3][0] == 'n' ? false : true;
        //     experiment(param);
    //  }

       
        // std::cout << file << std::endl;
        param.indexFileName =argv[1];// "anti_2_3000_rtree_5.txt"
        param.queryFileName = argv[2]; // "query_anti_3.txt"
        param.k = param.queryFileName[param.queryFileName.size() - 5] - '0';
        param.k = extractNumberFromFilename(param.queryFileName);
        param.opt = argv[3][0] == 'n' ? false : true;
        experiment(param);
    }
}

int main(int argc, char* argv[])
{
    // test_bitset();
    //experiment();
    // test_SIC();
    // test_SVC();
    // test_getDistance();
    // test_STLD();
    std::cout << "running ..." << std::endl;
    run(argc, argv);
}