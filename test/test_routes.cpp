#include "av_connect.hpp"
#include <iostream>
#include <vector>

using namespace http;

// Helper function to print match results
void print_match_info(const std::string &test_url,
                      const route::match_result &result) {
  std::cout << "\nTesting URL: " << test_url << std::endl;
  if (result.matched) {
    std::cout << "✓ Matched!" << std::endl;
    std::cout << "  Method: " << method_to_string(result.method) << std::endl;
    std::cout << "  Original path: " << result.original_path << std::endl;
    if (!result.params.empty()) {
      std::cout << "  Parameters:" << std::endl;
      for (const auto &[key, value] : result.params) {
        std::cout << "    " << key << " = " << value << std::endl;
      }
    }
  } else {
    std::cout << "✗ No match" << std::endl;
    std::cout << "  Method tried: " << method_to_string(result.method) << std::endl;
  }
  std::cout << std::string(50, '-') << std::endl;
}

// Structure to hold test cases
struct RouteTestCase {
  std::string name;
  std::string url;
  http::method method;
  bool should_match;
  std::unordered_map<std::string, std::string> expected_params;

  RouteTestCase(const std::string &n, const std::string &u, http::method m,
                bool match,
                std::unordered_map<std::string, std::string> params = {})
      : name(n), url(u), method(m), should_match(match),
        expected_params(std::move(params)) {}
};

// Function to verify test results
bool verify_test_case(const RouteTestCase &test,
                      const route::match_result &result) {
  std::cout << "\nVerifying test case: " << test.name << std::endl;
  std::cout << "  Method: " << method_to_string(test.method) << std::endl;
  std::cout << "  URL: " << test.url << std::endl;
  std::cout << "  Expected match: " << (test.should_match ? "yes" : "no") << std::endl;
  
  if (result.matched != test.should_match) {
    std::cout << "❌ Test failed: " << test.name << std::endl;
    std::cout << "   Expected match: " << (test.should_match ? "yes" : "no")
              << ", got: " << (result.matched ? "yes" : "no") << std::endl;
    return false;
  }

  if (result.matched) {
    if (result.method != test.method) {
      std::cout << "❌ Test failed: " << test.name << std::endl;
      std::cout << "   Method mismatch. Expected: " << method_to_string(test.method)
                << ", got: " << method_to_string(result.method) << std::endl;
      return false;
    }

    if (result.params != test.expected_params) {
      std::cout << "❌ Test failed: " << test.name << std::endl;
      std::cout << "   Parameter mismatch" << std::endl;
      std::cout << "   Expected params:" << std::endl;
      for (const auto &[key, value] : test.expected_params) {
        std::cout << "     " << key << " = " << value << std::endl;
      }
      std::cout << "   Got params:" << std::endl;
      for (const auto &[key, value] : result.params) {
        std::cout << "     " << key << " = " << value << std::endl;
      }
      return false;
    }
  }

  std::cout << "✅ Test passed: " << test.name << std::endl;
  return true;
}

int main() {

  {
    std::cout << "\nTesting route_info pattern matching directly:\n" << std::string(50, '=') << std::endl;
    
    // Create a list of route_info test cases
    struct RoutePatternTest {
      std::string name;
      std::string pattern;
      std::string test_path;
      bool should_match;
      std::unordered_map<std::string, std::string> expected_params;
    };

    std::vector<RoutePatternTest> pattern_tests = {
      // Basic static routes - with and without version
      {"Static path with version", "/v1/models", "/v1/models", true, {}},
      {"Static path without version", "/models", "/models", true, {}},
      {"Static path no match", "/v1/models", "/v1/model", false, {}},
      
      // Single parameter routes - with and without version
      {"Single parameter with version", "/v1/models/{model}", "/v1/models/gpt-4", true, {{"model", "gpt-4"}}},
      {"Single parameter without version", "/models/{model}", "/models/gpt-4", true, {{"model", "gpt-4"}}},
      {"Single parameter with numbers", "/v1/models/{model}", "/v1/models/gpt-4-32k", true, {{"model", "gpt-4-32k"}}},
      {"Single parameter no match", "/v1/models/{model}", "/v1/models/", false, {}},
      
      // Multiple parameters - with and without version
      {"Multiple parameters with version", "/v1/models/{model}/versions/{version}", "/v1/models/gpt-4/versions/v2", true, 
        {{"model", "gpt-4"}, {"version", "v2"}}},
      {"Multiple parameters without version", "/models/{model}/versions/{version}", "/models/gpt-4/versions/v2", true, 
        {{"model", "gpt-4"}, {"version", "v2"}}},
      {"Multiple parameters no match", "/v1/models/{model}/versions/{version}", "/v1/models/gpt-4/versions", false, {}},
      
      // Edge cases
      {"Trailing slash", "/v1/models/", "/v1/models", false, {}},
      {"Extra slashes", "/v1/models/{model}", "/v1/models//gpt-4", false, {}},
      {"Invalid characters", "/v1/models/{model}", "/v1/models/gpt@4", false, {}},
      
      // Version specific cases
      {"Wrong version number", "/v1/models", "/v2/models", false, {}},
      {"Version in wrong place", "/models/v1", "/models/v1", true, {}},
      {"Version as parameter", "/v{version}/models", "/v1/models", true, {{"version", "1"}}}
    };

    int passed = 0;
    int total = pattern_tests.size();

    for (const auto& test : pattern_tests) {
      std::cout << "\nTesting: " << test.name << std::endl;
      std::cout << "Pattern: " << test.pattern << std::endl;
      std::cout << "Test path: " << test.test_path << std::endl;
      
      // Create route_info instance
      route::route_info info(test.pattern);
      
      // Try to match
      std::smatch matches;
      bool matched = std::regex_match(test.test_path, matches, info.pattern);
      
      std::cout << "Match result: " << (matched ? "✓" : "✗") << std::endl;
      
      if (matched != test.should_match) {
        std::cout << "❌ Test failed: Expected match=" << test.should_match 
                  << ", got match=" << matched << std::endl;
        continue;
      }
      
      if (matched) {
        // Check parameters
        std::unordered_map<std::string, std::string> params;
        for (size_t i = 0; i < info.param_names.size(); ++i) {
          if (i + 1 < matches.size()) {
            params[info.param_names[i]] = matches[i + 1].str();
          }
        }
        
        if (params != test.expected_params) {
          std::cout << "❌ Parameter mismatch!" << std::endl;
          std::cout << "Expected parameters:" << std::endl;
          for (const auto& [key, value] : test.expected_params) {
            std::cout << "  " << key << " = " << value << std::endl;
          }
          std::cout << "Got parameters:" << std::endl;
          for (const auto& [key, value] : params) {
            std::cout << "  " << key << " = " << value << std::endl;
          }
          continue;
        }
      }
      
      std::cout << "✅ Test passed!" << std::endl;
      passed++;
    }

    // Print summary for route_info tests
    std::cout << "\nRoute Info Test Summary:\n" << std::string(50, '=') << std::endl;
    std::cout << "Total tests: " << total << std::endl;
    std::cout << "Passed: " << passed << std::endl;
    std::cout << "Failed: " << (total - passed) << std::endl;
    std::cout << "Success rate: " << (passed * 100.0 / total) << "%" << std::endl;
    std::cout << std::string(50, '=') << std::endl;
  }

  try {
    // Create route instance
    route api_routes;

    // Register routes (without handlers since we're just testing matching)
    std::cout << "Registering routes:" << std::endl;
    
    // Versioned routes
    std::cout << "  GET /v1/models" << std::endl;
    api_routes.get("/v1/models", [](std::shared_ptr<response>) {});
    
    std::cout << "  GET /v1/models/{model}" << std::endl;
    api_routes.get("/v1/models/{model}", [](std::shared_ptr<response>) {});
    
    std::cout << "  POST /v1/chat/completions" << std::endl;
    api_routes.post("/v1/chat/completions", [](std::shared_ptr<response>) {});
    
    std::cout << "  PUT /v1/models/{model}" << std::endl;
    api_routes.put("/v1/models/{model}", [](std::shared_ptr<response>) {});
    
    std::cout << "  DELETE /v1/models/{model}" << std::endl;
    api_routes.del("/v1/models/{model}", [](std::shared_ptr<response>) {});

    // Non-versioned routes
    std::cout << "  GET /models" << std::endl;
    api_routes.get("/models", [](std::shared_ptr<response>) {});
    
    std::cout << "  GET /models/{model}" << std::endl;
    api_routes.get("/models/{model}", [](std::shared_ptr<response>) {});
    
    std::cout << "  POST /chat/completions" << std::endl;
    api_routes.post("/chat/completions", [](std::shared_ptr<response>) {});

    // Define test cases
    std::vector<RouteTestCase> tests = {
        // Valid versioned routes
        RouteTestCase("List models (v1)", "/v1/models", http::method::get, true),
        RouteTestCase("Get specific model (v1)", "/v1/models/gpt-4",
                      http::method::get, true, {{"model", "gpt-4"}}),
        RouteTestCase("Chat completion (v1)", "/v1/chat/completions",
                      http::method::post, true),
        RouteTestCase("Update model (v1)", "/v1/models/gpt-4", http::method::put,
                      true, {{"model", "gpt-4"}}),
        RouteTestCase("Delete model (v1)", "/v1/models/gpt-4", http::method::del,
                      true, {{"model", "gpt-4"}}),

        // Valid non-versioned routes
        RouteTestCase("List models", "/models", http::method::get, true),
        RouteTestCase("Get specific model", "/models/gpt-4",
                      http::method::get, true, {{"model", "gpt-4"}}),
        RouteTestCase("Chat completion", "/chat/completions",
                      http::method::post, true),

        // Invalid routes
        RouteTestCase("Non-existent route", "/v1/invalid", http::method::get,
                      false),
        RouteTestCase("Wrong version", "/v2/models", http::method::get,
                      false),
        RouteTestCase("Wrong method for existing route", "/v1/models",
                      http::method::post, false),
        RouteTestCase("Invalid model parameter", "/v1/models/",
                      http::method::get, false),
        RouteTestCase("Extra slashes", "/v1/models//gpt-4", http::method::get,
                      false),
        RouteTestCase("Missing version but requiring v1", "/models/gpt-4",
                      http::method::put, false), // PUT is only registered with v1
        RouteTestCase("Version in wrong place", "/models/v1/gpt-4",
                      http::method::get, false)
    };

    // Run tests
    std::cout << "\nRunning route matching tests:\n"
              << std::string(50, '=') << std::endl;
    int passed = 0;
    int total = tests.size();

    for (const auto &test : tests) {
      auto result = api_routes.match_url(test.method, test.url);
      print_match_info(test.url, result);
      if (verify_test_case(test, result)) {
        passed++;
      }
      std::cout << std::string(50, '-') << std::endl;
    }

    // Print summary
    std::cout << "\nTest Summary:\n" << std::string(50, '=') << std::endl;
    std::cout << "Total tests: " << total << std::endl;
    std::cout << "Passed: " << passed << std::endl;
    std::cout << "Failed: " << (total - passed) << std::endl;
    std::cout << "Success rate: " << (passed * 100.0 / total) << "%"
              << std::endl;

    return (passed == total) ? 0 : 1;

  } catch (std::exception &e) {
    std::cerr << "Exception: " << e.what() << std::endl;
    return 1;
  }
}
