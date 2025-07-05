/* Copyright (c) 2024-2024 Harry Le (avble.harry at gmail dot com)
   Example of using chunked responses with both simple and advanced usage
*/

#include "../lib/http.hpp"
#include <chrono>
#include <thread>
#include <queue>
#include <random>
#include <future>
#include <atomic>


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

// Helper function to send chunks sequentially using callbacks
void send_chunk_sequence(std::shared_ptr<response> res, int current_chunk, int total_chunks) {
    if (current_chunk >= total_chunks) {
        // All chunks sent, end the response
        res->chunk_end_async([](bool success) {
            if (!success) {
                HTTP_LOG_ERROR("Failed to end chunked response");
            }
        });
        return;
    }

    std::string chunk = "Chunk " + std::to_string(current_chunk) + "\n";
    
    res->chunk_write_async(chunk, [res, current_chunk, total_chunks](bool success) {
        if (!success) {
            HTTP_LOG_ERROR("Failed to write chunk %d", current_chunk);
            return;
        }

        // Add delay and continue with next chunk
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        send_chunk_sequence(res, current_chunk + 1, total_chunks);
    });
}
// Simple chunked response example
void handle_simple_chunks(std::shared_ptr<response> res) {
    // Start chunked response
    res->chunk_start_async([res](bool success) {
        if (!success) {
            HTTP_LOG_ERROR("Failed to start chunked response");
            return;
        }

        // Chain the chunk writes using callbacks to avoid threading issues
        send_chunk_sequence(res, 0, 5);
    });
}

// Async chunk generation helper
struct AsyncChunkState {
    std::shared_ptr<response> res;
    std::unique_ptr<DataGenerator> generator;
    std::atomic<int> chunks_remaining{0};
};

void generate_next_chunk(std::shared_ptr<AsyncChunkState> state) {
    if (state->chunks_remaining <= 0) {
        // All chunks generated, end the response
        state->res->chunk_end_async([](bool success) {
            if (!success) {
                HTTP_LOG_ERROR("Failed to end advanced chunked response");
            }
        });
        return;
    }

    // Generate data in a separate thread to avoid blocking
    std::thread([state]() {
        auto data = state->generator->get_data();
        
        // Write the chunk
        state->res->chunk_write_async(data, [state](bool success) {
            if (!success) {
                HTTP_LOG_ERROR("Failed to write advanced chunk");
                return;
            }

            state->chunks_remaining--;
            
            // Schedule next chunk generation
            std::thread([state]() {
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
                generate_next_chunk(state);
            }).detach();
        });
    }).detach();
}

// Fixed advanced chunked response with proper async handling
void handle_advanced_chunks(std::shared_ptr<response> res) {
    // Use async approach to avoid blocking the main thread
    res->chunk_start_async([res](bool success) {
        if (!success) {
            HTTP_LOG_ERROR("Failed to start advanced chunked response");
            return;
        }

        // Create a shared state to manage the async operation
        auto state = std::make_shared<AsyncChunkState>();
        state->res = res;
        state->generator = std::make_unique<DataGenerator>(1024);
        state->chunks_remaining = 20;
        
        // Start the async chunk generation
        generate_next_chunk(state);
    });
}



// Alternative simpler approach without threading
void handle_simple_chunks_no_threading(std::shared_ptr<response> res) {
    res->chunk_start_async([res](bool success) {
        if (!success) {
            return;
        }

        // Use a timer-based approach instead of sleep
        auto timer = std::make_shared<boost::asio::steady_timer>(io_context::ioc);
        auto chunk_count = std::make_shared<int>(0);
        
        // Create a shared function object to avoid self-capture issue
        auto send_next_chunk = std::make_shared<std::function<void()>>();
        
        *send_next_chunk = [res, timer, chunk_count, send_next_chunk]() {
            if (*chunk_count >= 5) {
                res->chunk_end_async();
                return;
            }

            std::string chunk = "Chunk " + std::to_string(*chunk_count) + "\n";
            (*chunk_count)++;
            
            res->chunk_write_async(chunk, [timer, send_next_chunk](bool success) {
                if (!success) return;
                
                timer->expires_after(std::chrono::milliseconds(100));
                timer->async_wait([send_next_chunk](const boost::system::error_code& ec) {
                    if (!ec) {
                        (*send_next_chunk)();
                    }
                });
            });
        };

        (*send_next_chunk)();
    });
}

// Helper function for recursive chunk sending
void send_chunk_recursive(std::shared_ptr<response> res, int current, int total) {
    if (current >= total) {
        res->chunk_end_async();
        return;
    }

    std::string chunk = "Chunk " + std::to_string(current) + "\n";
    res->chunk_write_async(chunk, [res, current, total](bool success) {
        if (success) {
            send_chunk_recursive(res, current + 1, total);
        }
    });
}

void handle_simple_chunks_immediate(std::shared_ptr<response> res) {
    res->chunk_start_async([res](bool success) {
        if (!success) {
            return;
        }

        // Chain chunks using recursive callback pattern
        send_chunk_recursive(res, 0, 5);
    });
}


int main(int argc, char *args[]) {
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

  router.get("/simple_chunks_safe", handle_simple_chunks_no_threading);
    // Immediate execution without delays
    router.get("/simple_chunks_immediate", handle_simple_chunks_immediate);

  // Start server
  http::start_server(port, std::ref(router));

  return 0;
}
