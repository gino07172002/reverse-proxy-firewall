#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <set>
#include <thread>
#include <chrono>
#include <fstream>
#include <sstream>
#include <regex>
#include <ctime>
#include <iomanip>
#include <signal.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <cstring>
#include <netinet/tcp.h>

class SSHProxyWhitelistMonitor {
public:
    ~SSHProxyWhitelistMonitor() {
        if (running) {
            stop();
        }
        cleanupFirewallRules();

    }
private:


    std::set<std::string> whitelist;
    std::map<std::string, std::time_t> connectionAttempts;
    std::map<std::string, std::time_t> rejectionLog;
    std::string whitelistFile;
    std::string logFile;
    int monitorPort;
    int proxyPort;
    bool running;
    std::string rejectionMethod;

    // 記錄日誌
    void log(const std::string& message, const std::string& level = "INFO") {
        std::time_t now = std::time(nullptr);
        std::tm* timeinfo = std::localtime(&now);
        std::ofstream logStream(logFile, std::ios::app);
        logStream << "[" << std::put_time(timeinfo, "%Y-%m-%d %H:%M:%S")
                  << "] [" << level << "] " << message << std::endl;
        logStream.close();

        // 同時輸出到控制台
        std::cout << "[" << std::put_time(timeinfo, "%Y-%m-%d %H:%M:%S")
                  << "] [" << level << "] " << message << std::endl;
    }

    // 載入白名單
    void loadWhitelist() {
        std::ifstream file(whitelistFile);
        std::string line;
        whitelist.clear();

        if (file.is_open()) {
            while (std::getline(file, line)) {
                if (!line.empty() && line[0] != '#') {
                    // 移除前後空白
                    line.erase(0, line.find_first_not_of(" \t"));
                    line.erase(line.find_last_not_of(" \t") + 1);
                    if (!line.empty()) {
                        whitelist.insert(line);
                    }
                }
            }
            file.close();
            log("白名單載入完成，共 " + std::to_string(whitelist.size()) + " 個項目");
        } else {
            log("白名單檔案不存在，創建新檔案: " + whitelistFile);
            std::ofstream newFile(whitelistFile);
            newFile << "# SSH反向代理白名單\n";
            newFile << "# 格式：IP地址、用戶名或IP範圍\n";
            newFile << "# 範例：\n";
            newFile << "# 192.168.1.100\n";
            newFile << "# admin\n";
            newFile << "# 192.168.1.0/24\n";
            newFile << "# alloweduser@192.168.1.50\n";
            newFile.close();
        }
    }

    // 儲存白名單
    void saveWhitelist() {
        std::ofstream file(whitelistFile);
        file << "# SSH反向代理白名單\n";
        file << "# 格式：IP地址、用戶名或IP範圍\n";
        std::time_t now = std::time(nullptr);
        std::tm* timeinfo = std::localtime(&now);
        file << "# 更新時間: " << std::put_time(timeinfo, "%Y-%m-%d %H:%M:%S") << "\n";

        for (const auto& item : whitelist) {
            file << item << "\n";
        }
        file.close();
        log("白名單已儲存");
    }

    // 檢查IP是否在網段範圍內
    bool isInSubnet(const std::string& ip, const std::string& subnet) {
        size_t slashPos = subnet.find('/');
        if (slashPos == std::string::npos) {
            return ip == subnet;
        }

        std::string network = subnet.substr(0, slashPos);
        int prefix = std::stoi(subnet.substr(slashPos + 1));

        struct in_addr ipAddr, networkAddr;
        if (inet_aton(ip.c_str(), &ipAddr) == 0 ||
                inet_aton(network.c_str(), &networkAddr) == 0) {
            return false;
        }

        uint32_t mask = (~0U) << (32 - prefix);
        return (ntohl(ipAddr.s_addr) & mask) == (ntohl(networkAddr.s_addr) & mask);
    }

    // 檢查是否在白名單中
    bool isWhitelisted(const std::string& ip, const std::string& user) {
        // 檢查完整的用戶@IP格式
        std::string userAtIp = user + "@" + ip;
        if (whitelist.count(userAtIp) > 0) {
            return true;
        }

        // 檢查IP地址
        if (whitelist.count(ip) > 0) {
            return true;
        }

        // 檢查用戶名
        if (whitelist.count(user) > 0) {
            return true;
        }

        // 檢查IP範圍
        for (const auto& item : whitelist) {
            if (item.find('/') != std::string::npos) {
                if (isInSubnet(ip, item)) {
                    return true;
                }
            }
        }

        return false;
    }

    // 解析ss輸出獲取連線資訊 - 修正版本
    std::vector<std::pair<std::string, std::string>> getActiveConnections() {
        std::vector<std::pair<std::string, std::string>> connections;

        // 使用ss命令獲取連線到指定端口的連線
        std::string command = "ss -tn state established '( sport = :" + std::to_string(monitorPort) + " )'";
        FILE* pipe = popen(command.c_str(), "r");

        if (pipe) {
            char buffer[512];
            while (fgets(buffer, sizeof(buffer), pipe)) {
                std::string line(buffer);
                if (line.find("ESTAB") != std::string::npos || line.find("127.0.0.1") == std::string::npos) {
                    // 使用更精確的正規表達式解析ss輸出
                    // ss輸出格式: ESTAB 0 0 本地IP:本地端口 遠端IP:遠端端口
                    std::regex connRegex(R"(ESTAB\s+\d+\s+\d+\s+([^\s]+):(\d+)\s+([^\s]+):(\d+))");
                    std::smatch match;

                    if (std::regex_search(line, match, connRegex)) {
                        std::string localIp = match[1].str();
                        std::string localPort = match[2].str();
                        std::string remoteIp = match[3].str();
                        std::string remotePort = match[4].str();

                        // 確認這是連線到我們監控端口的連線
                        if (localPort == std::to_string(monitorPort)) {
                            connections.push_back({remoteIp, line});
                            log("檢測到連線: " + remoteIp + ":" + remotePort + " -> " + localIp + ":" + localPort, "DEBUG");
                        }
                    }
                }
            }
            pclose(pipe);
        }

        // 如果ss命令沒有結果，嘗試使用netstat作為備選方案
        if (connections.empty()) {
            std::string command2 = "netstat -tn | grep :" + std::to_string(monitorPort) + " | grep ESTABLISHED";
            FILE* pipe2 = popen(command2.c_str(), "r");

            if (pipe2) {
                char buffer[512];
                while (fgets(buffer, sizeof(buffer), pipe2)) {
                    std::string line(buffer);
                    // netstat輸出格式: tcp 0 0 本地IP:本地端口 遠端IP:遠端端口 ESTABLISHED
                    std::regex netstatRegex(R"(tcp\s+\d+\s+\d+\s+([^\s]+):(\d+)\s+([^\s]+):(\d+)\s+ESTABLISHED)");
                    std::smatch match;

                    if (std::regex_search(line, match, netstatRegex)) {
                        std::string localIp = match[1].str();
                        std::string localPort = match[2].str();
                        std::string remoteIp = match[3].str();
                        std::string remotePort = match[4].str();

                        if (localPort == std::to_string(monitorPort)) {
                            connections.push_back({remoteIp, line});
                            log("檢測到連線 (netstat): " + remoteIp + ":" + remotePort + " -> " + localIp + ":" + localPort, "DEBUG");
                        }
                    }
                }
                pclose(pipe2);
            }
        }

        return connections;
    }

    // 獲取通過SSH連線的用戶名 - 改進版本
    std::string getSSHUser(const std::string& ip) {
        // 方法1：檢查who命令
        std::string command = "who | grep " + ip + " | awk '{print $1}' | head -1";
        FILE* pipe = popen(command.c_str(), "r");

        if (pipe) {
            char buffer[256];
            if (fgets(buffer, sizeof(buffer), pipe)) {
                std::string user(buffer);
                if (!user.empty() && user.back() == '\n') {
                    user.pop_back();
                }
                pclose(pipe);
                if (!user.empty()) {
                    return user;
                }
            }
            pclose(pipe);
        }

        // 方法2：檢查SSH進程 - 改進版本
        command = "ps aux | grep 'sshd:' | grep -v grep | grep -v 'sshd: /usr/sbin/sshd' | head -1";
        pipe = popen(command.c_str(), "r");

        if (pipe) {
            char buffer[512];
            if (fgets(buffer, sizeof(buffer), pipe)) {
                std::string line(buffer);
                pclose(pipe);

                // 從sshd進程中提取用戶名
                std::regex userRegex(R"(sshd:\s*([^\s\[]+))");
                std::smatch match;
                if (std::regex_search(line, match, userRegex)) {
                    return match[1].str();
                }
            }
            pclose(pipe);
        }

        // 方法3：檢查登入日誌
        command = "last -i | grep " + ip + " | grep 'still logged in\\|pts' | head -1 | awk '{print $1}'";
        pipe = popen(command.c_str(), "r");

        if (pipe) {
            char buffer[256];
            if (fgets(buffer, sizeof(buffer), pipe)) {
                std::string user(buffer);
                if (!user.empty() && user.back() == '\n') {
                    user.pop_back();
                }
                pclose(pipe);
                if (!user.empty() && user != "reboot") {
                    return user;
                }
            }
            pclose(pipe);
        }

        return "unknown";
    }

    // 優雅地拒絕連線
    void rejectConnection(const std::string& ip, const std::string& method) {
        if (method == "reset") {
            // 發送TCP RST包
            // 使用iptables拒絕封包，並送出 TCP reset
            std::string command = "iptables -A INPUT -s " + ip + " -p tcp --dport " +
                    std::to_string(monitorPort) + " -j REJECT --reject-with tcp-reset";
            system(command.c_str());

            // 30秒後移除規則
            std::thread([=]() {
                std::this_thread::sleep_for(std::chrono::seconds(5));

                // 移除 REJECT 規則
                std::string removeCommand = "iptables -D INPUT -s " + ip + " -p tcp --dport " +
                        std::to_string(monitorPort) + " -j REJECT --reject-with tcp-reset 2>/dev/null";
                system(removeCommand.c_str());

                // 移除 conntrack 快取
                std::string conntrackClear = "conntrack -D -s " + ip + " 2>/dev/null";
                system(conntrackClear.c_str());
            }).detach();

            log("已設定防火牆規則拒絕來自 " + ip + " 的連線（TCP reset）", "REJECT");

        } else if (method == "drop") {
            // 使用iptables丟棄封包
            std::string command = "iptables -A INPUT -s " + ip + " -p tcp --dport " +
                    std::to_string(monitorPort) + " -j DROP";
            system(command.c_str());

            // 30秒後移除規則
            std::thread([=]() {
                std::this_thread::sleep_for(std::chrono::seconds(30));
                std::string removeCommand = "iptables -D INPUT -s " + ip + " -p tcp --dport " +
                        std::to_string(monitorPort) + " -j DROP 2>/dev/null";
                system(removeCommand.c_str());
            }).detach();

            log("已設定防火牆規則阻擋來自 " + ip + " 的連線", "REJECT");

        } else if (method == "reject") {
            std::string command = "iptables -A INPUT -s " + ip + " -p tcp --dport " +
                    std::to_string(monitorPort) + " -j REJECT --reject-with tcp-reset";
            system(command.c_str());

            // 5秒後移除規則（注意：這裡改成了5秒，但註釋說60秒）
            std::thread([=]() {
                std::this_thread::sleep_for(std::chrono::seconds(5));

                // 移除規則時要完全匹配創建時的規則
                std::string removeCommand = "iptables -D INPUT -s " + ip + " -p tcp --dport " +
                        std::to_string(monitorPort) + " -j REJECT --reject-with tcp-reset 2>/dev/null";
                system(removeCommand.c_str());

                log("已移除來自 " + ip + " 的拒絕規則", "REJECT_REMOVED");
            }).detach();

            log("已設定延遲規則讓來自 " + ip + " 的連線超時", "REJECT");
        } else {
            // 預設：直接終止連線
            std::string command = "ss -K dst " + ip + " dport = " + std::to_string(monitorPort);
            system(command.c_str());
            log("已終止來自 " + ip + " 的連線", "REJECT");
        }
    }

    void resetIptables() {
        std::cout<<" clear all iptables rules"<<std::endl;
        // 清除所有 INPUT 連接埠的 tcp-reset 規則
        std::string flushRejectRules =
            "iptables -S INPUT | grep 'REJECT --reject-with tcp-reset' | "
            "while read -r line; do "
            "iptables -D ${line#-A }; "
            "done";

        // 清除所有 conntrack 快取
        std::string flushConntrack = "conntrack -F";

        // 執行命令
        int result1 = system(flushRejectRules.c_str());
        int result2 = system(flushConntrack.c_str());

        std::cout << "[INFO] iptables REJECT 規則與 conntrack 快取已清除，所有白名單重開。\n";
    }

    // 新增：檢查防火牆規則是否已存在
    bool isFirewallRuleExists(const std::string& ip) {
        std::string command = "iptables -L INPUT -n | grep " + ip + " | grep " + std::to_string(monitorPort);
        int result = system(command.c_str());
        return result == 0;
    }

    // 新增：清理所有臨時防火牆規則
    void cleanupFirewallRules() {
        std::string command = "iptables -L INPUT --line-numbers -n | grep " + std::to_string(monitorPort) +
                " | grep -E '(DROP|REJECT|TARPIT)' | awk '{print $1}' | sort -rn | " +
                "xargs -r -I {} iptables -D INPUT {}";
        system(command.c_str());
        log("已清理所有臨時防火牆規則", "INFO");
    }

    // 監控連線
    void monitorConnections() {
        log("開始監控端口 " + std::to_string(monitorPort) + " 的連線");
        log("拒絕方法: " + rejectionMethod);

        while (running) {
            auto connections = getActiveConnections();

            for (const auto& conn : connections) {
                std::string ip = conn.first;
                std::string user = getSSHUser(ip);

                if (!isWhitelisted(ip, user)) {
                    // 記錄拒絕日誌
                    auto now = std::time(nullptr);
                    std::string key = ip + ":" + user;

                    if (rejectionLog.find(key) == rejectionLog.end() ||
                            now - rejectionLog[key] > 60) { // 1分鐘內不重複記錄
                        rejectionLog[key] = now;
                        log("拒絕未授權連線 - IP: " + ip + ", 用戶: " + user +
                            " (不在白名單中)", "REJECT");
                    }

                    rejectConnection(ip, rejectionMethod);
                } else {
                    // 記錄允許的連線
                    auto now = std::time(nullptr);
                    auto key = ip + ":" + user;

                    if (connectionAttempts.find(key) == connectionAttempts.end() ||
                            now - connectionAttempts[key] > 300) { // 5分鐘記錄一次
                        connectionAttempts[key] = now;
                        log("允許連線 - IP: " + ip + ", 用戶: " + user + " (在白名單中)", "ALLOW");
                    }
                }
            }

            // 重新載入白名單
            loadWhitelist();

            std::this_thread::sleep_for(std::chrono::seconds(3));
        }
    }

public:
    SSHProxyWhitelistMonitor(int port = 1234, const std::string& method = "reset") :
        monitorPort(port),
        proxyPort(port),
        running(false),
        rejectionMethod(method),
        whitelistFile("ssh_whitelist.txt"),
        logFile("ssh_whitelist_monitor.log") {
        loadWhitelist();
    }

    // 啟動監控
    void start() {
        running = true;
        log("SSH反向代理白名單監控器啟動");
        log("監控端口: " + std::to_string(monitorPort));
        log("白名單檔案: " + whitelistFile);
        log("日誌檔案: " + logFile);
        log("拒絕方法: " + rejectionMethod);

        std::thread monitorThread(&SSHProxyWhitelistMonitor::monitorConnections, this);

        // 命令行介面
        std::string command;
        std::cout << "\n=== SSH反向代理白名單監控器 ===" << std::endl;
        std::cout << "指令說明:" << std::endl;
        std::cout << "  add <ip_or_user>     - 添加到白名單" << std::endl;
        std::cout << "  remove <ip_or_user>  - 從白名單移除" << std::endl;
        std::cout << "  list                 - 顯示白名單" << std::endl;
        std::cout << "  status               - 顯示當前連線狀態" << std::endl;
        std::cout << "  reload               - 重新載入白名單" << std::endl;
        std::cout << "  method <reset|drop|delay> - 設定拒絕方法" << std::endl;
        std::cout << "  rejected             - 顯示最近被拒絕的連線" << std::endl;
        std::cout << "  debug                - 顯示除錯資訊" << std::endl;
        std::cout << "  quit                 - 退出程式" << std::endl;
        std::cout << "=================================" << std::endl;

        while (running) {
            std::cout << "\n> ";
            std::getline(std::cin, command);

            if (command == "quit" || command == "exit") {
                stop();
                break;
            } else if (command == "list") {
                showWhitelist();
            } else if (command == "status") {
                showStatus();
            } else if (command == "reload") {
                loadWhitelist();
            } else if (command == "rejected") {
                showRejectedConnections();
            } else if (command == "debug") {
                showDebugInfo();
            } else if (command.substr(0, 4) == "add ") {
                std::string item = command.substr(4);
                addToWhitelist(item);
            } else if (command.substr(0, 7) == "remove ") {
                std::string item = command.substr(7);
                removeFromWhitelist(item);
            } else if (command.substr(0, 7) == "method ") {
                std::string method = command.substr(7);
                setRejectionMethod(method);
            } else if (!command.empty()) {
                std::cout << "未知指令: " << command << std::endl;
            }
        }

        if (monitorThread.joinable()) {
            monitorThread.join();
        }
    }

    // 停止監控
    void stop() {
        running = false;
        log("SSH反向代理白名單監控器停止");
        resetIptables();
    }

    // 設定拒絕方法
    void setRejectionMethod(const std::string& method) {
        if (method == "reset" || method == "drop" || method == "reject" ) {
            rejectionMethod = method;
            log("拒絕方法設定為: " + method);
        } else {
            std::cout << "無效的拒絕方法: " << method << std::endl;
            std::cout << "可用方法:" << std::endl;
            std::cout << "  reset  - 使用 ss 命令發送 TCP RST (有備援機制)" << std::endl;
            std::cout << "  drop   - 使用 iptables 丟棄封包" << std::endl;
            std::cout << "  reject - 使用 iptables 發送 RST 包" << std::endl;
            std::cout << "  delay  - 延遲回應讓連線超時" << std::endl;
            std::cout << "  kill   - 直接終止相關進程" << std::endl;
        }
    }

    // 添加到白名單
    void addToWhitelist(const std::string& item) {
        whitelist.insert(item);
        saveWhitelist();
        log("已添加到白名單: " + item);
    }

    // 從白名單移除
    void removeFromWhitelist(const std::string& item) {
        if (whitelist.erase(item) > 0) {
            saveWhitelist();
            log("已從白名單移除: " + item);
        } else {
            std::cout << "項目不在白名單中: " << item << std::endl;
        }
    }

    // 顯示白名單
    void showWhitelist() {
        std::cout << "\n=== 白名單 (" << whitelist.size() << " 項目) ===" << std::endl;
        for (const auto& item : whitelist) {
            std::cout << "  " << item << std::endl;
        }
        std::cout << "=================================" << std::endl;
    }

    // 顯示被拒絕的連線
    void showRejectedConnections() {
        std::cout << "\n=== 最近被拒絕的連線 ===" << std::endl;
        for (const auto& rejection : rejectionLog) {
            std::time_t timestamp = rejection.second;
            std::tm* timeinfo = std::localtime(&timestamp);
            std::cout << "  " << std::put_time(timeinfo, "%Y-%m-%d %H:%M:%S")
                      << " - " << rejection.first << std::endl;
        }
        std::cout << "=========================" << std::endl;
    }

    // 顯示除錯資訊
    void showDebugInfo() {
        std::cout << "\n=== 除錯資訊 ===" << std::endl;

        // 顯示ss命令結果
        std::string command = "ss -tn state established '( sport = :" + std::to_string(monitorPort) + " )'";
        std::cout << "執行指令: " << command << std::endl;
        system(command.c_str());

        std::cout << "\n執行指令: netstat -tn | grep :" << monitorPort << std::endl;
        command = "netstat -tn | grep :" + std::to_string(monitorPort);
        system(command.c_str());

        std::cout << "================" << std::endl;
    }

    // 顯示當前狀態
    void showStatus() {
        std::cout << "\n=== 系統狀態 ===" << std::endl;
        std::cout << "監控端口: " << monitorPort << std::endl;
        std::cout << "白名單項目: " << whitelist.size() << std::endl;
        std::cout << "拒絕方法: " << rejectionMethod << std::endl;
        std::cout << "運行狀態: " << (running ? "執行中" : "已停止") << std::endl;

        auto connections = getActiveConnections();
        std::cout << "當前連線數: " << connections.size() << std::endl;

        for (const auto& conn : connections) {
            std::string ip = conn.first;
            std::string user = getSSHUser(ip);
            bool allowed = isWhitelisted(ip, user);
            std::cout << "  " << ip << " (" << user << ") - "
                      << (allowed ? "允許" : "拒絕") << std::endl;
        }
        std::cout << "==================" << std::endl;
    }
};

// 全域變數用於信號處理
SSHProxyWhitelistMonitor* g_monitor = nullptr;

// 信號處理函數
void signalHandler(int signum) {
    if (g_monitor) {
        g_monitor->stop();
    }
    exit(signum);
}

int main(int argc, char* argv[]) {
    int port = 2234;
    std::string method = "reset";

    // 解析命令行參數
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "-p" && i + 1 < argc) {
            port = std::atoi(argv[++i]);
            if (port <= 0 || port > 65535) {
                std::cerr << "無效的端口號: " << argv[i] << std::endl;
                return 1;
            }
        } else if (arg == "-m" && i + 1 < argc) {
            method = argv[++i];
            if (method != "reset" && method != "drop" && method != "delay") {
                std::cerr << "無效的拒絕方法: " << method << std::endl;
                std::cerr << "可用方法: reset, drop, delay" << std::endl;
                return 1;
            }
        } else if (arg == "-h" || arg == "--help") {
            std::cout << "使用方法: " << argv[0] << " [選項]" << std::endl;
            std::cout << "選項:" << std::endl;
            std::cout << "  -p <port>     指定監控端口 (預設: 1234)" << std::endl;
            std::cout << "  -m <method>   指定拒絕方法 (reset|drop|delay, 預設: reset)" << std::endl;
            std::cout << "  -h, --help    顯示此幫助訊息" << std::endl;
            std::cout << std::endl;
            std::cout << "拒絕方法說明:" << std::endl;
            std::cout << "  reset - 發送TCP RST包立即斷開連線" << std::endl;
            std::cout << "  drop  - 使用防火牆丟棄封包，看起來像網路問題" << std::endl;
            std::cout << "  delay - 延遲回應直到連線超時" << std::endl;
            std::cout << std::endl;
            std::cout << "除錯技巧:" << std::endl;
            std::cout << "  啟動程式後可以使用 'debug' 指令查看連線檢測狀況" << std::endl;
            std::cout << "  使用 'status' 指令查看當前連線和白名單狀態" << std::endl;
            return 0;
        }
    }

    // 檢查是否有足夠權限執行系統命令
    if (geteuid() != 0) {
        std::cout << "警告: 建議以root權限執行此程式以確保所有功能正常運作" << std::endl;
    }

    // 設置信號處理
    signal(SIGINT, signalHandler);
    signal(SIGTERM, signalHandler);

    SSHProxyWhitelistMonitor monitor(port, method);
    g_monitor = &monitor;

    try {
        monitor.start();
    } catch (const std::exception& e) {
        std::cerr << "錯誤: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
