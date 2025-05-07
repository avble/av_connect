#pragma once

#include "json.hpp"

#include <string>
#include <time.h>

static std::string oai_make_stream(std::string data, bool is_chat = true)
{
    nlohmann::json js{ { "id", "chatcmpl-123" },
                       { "object", is_chat ? "chat.completion.chunk" : "text_completion" },
                       { "created", std::time(0) },
                       { "model", "gpt-4o-mini" },
                       { "system_fingerprint", "fp_44709d6fcb" },
                       { "choices",
                         { { { "index", 0 },
                             is_chat ? nlohmann::json{ "delta", { { "role", "assistant" }, { "content", data } } }
                                     : nlohmann::json{ "text", data },
                             { "logprobs", nullptr },
                             { "finish_reason", nullptr } } } } };

    return js.dump() + "\n\n";
};
