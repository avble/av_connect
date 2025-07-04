/* Copyright (c) 2024-2024 Harry Le (avble.harry at gmail dot com)
   Example of using chunked responses with both simple and advanced usage
*/

#include "../lib/http.hpp"
#include <chrono>
#include <thread>
#include <queue>
#include <random>

using namespace std::placeholders;
using namespace http;

// Simulates a data source that generates data at irregular intervals
class DataGenerator {
public:
    DataGenerator(size_t max_size = 1024) : max_size_(max_size) {}

    std::string get_data() {
        static std::random_device rd;
        static std::mt19937 gen(rd());
        static std::uniform_int_distribution<> size_dis(10, max_size_);
        static std::uniform_int_distribution<> delay_dis(50, 200);

        // Simulate processing delay
        std::this_thread::sleep_for(std::chrono::milliseconds(delay_dis(gen)));

        size_t size = size_dis(gen);
        std::string data;
        data.reserve(size);
        for (size_t i = 0; i < size; ++i) {
            data += static_cast<char>('0' + (i % 10));
        }
        return data;
    }

private:
    size_t max_size_;
};

// Simple chunked response example
void handle_simple_chunks(std::shared_ptr<response> res) {
    res->chunk_start();

    // Send 5 chunks
    for (int i = 0; i < 5; ++i) {
        std::string chunk = "Chunk " + std::to_string(i) + "\n";
        res->chunk_write(chunk);
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    res->chunk_end();
}

// Advanced chunked response with queue management
void handle_advanced_chunks(std::shared_ptr<response> res) {
    // Set a small queue limit to demonstrate queue management
    res->set_queue_limit(4096);  // 4KB queue limit

    DataGenerator generator(1024);  // Generate chunks up to 1KB
    std::queue<std::string> pending_data;
    bool sending = true;

    res->chunk_start();

    // Producer thread - generates data
    std::thread producer([&]() {
        for (int i = 0; i < 20 && sending; ++i) {
            auto data = generator.get_data();
            
            // Try to write directly
            if (!res->try_chunk_write(data)) {
                // Queue is full, store for later
                pending_data.push(std::move(data));
                HTTP_LOG_INFO("Queue full, stored chunk for later");
            }
        }
        sending = false;
    });

    // Consumer thread - processes pending data when queue has space
    std::thread consumer([&]() {
        while (sending || !pending_data.empty()) {
            if (!pending_data.empty() && !res->is_queue_full()) {
                auto& data = pending_data.front();
                if (res->try_chunk_write(data)) {
                    pending_data.pop();
                    HTTP_LOG_INFO("Sent pending chunk, %zu remaining", pending_data.size());
                }
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
    });

    producer.join();
    consumer.join();
    res->chunk_end();
}

int main(int argc, char* args[]) {
    if (argc != 3) {
        std::cerr << "\nUsage: " << args[0] << " address port\n"
                  << "Example: \n"
                  << args[0] << " 0.0.0.0 12345" << std::endl;
        return -1;
    }

    std::string addr(args[1]);
    uint16_t port = static_cast<uint16_t>(std::atoi(args[2]));

    http::route router;

    // Simple chunked response example
    router.get("/simple_chunks", handle_simple_chunks);

    // Advanced chunked response example
    router.get("/advanced_chunks", handle_advanced_chunks);

    // Start server
    http::start_server(port, std::ref(router));

    return 0;
}
