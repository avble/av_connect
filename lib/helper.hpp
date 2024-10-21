#pragma once

#include "json.hpp"

#include <string>
#include <time.h>

static std::string oai_make_stream(std::string data)
{
    nlohmann::json js{ { "id", "chatcmpl-123" },
                       { "object", "chat.completion.chunk" },
                       { "created", std::time(0) },
                       { "model", "gpt-4o-mini" },
                       { "system_fingerprint", "fp_44709d6fcb" },
                       { "choices",
                         { { { "index", 0 },
                             { "delta", { { "role", "assistant" }, { "content", data } } },
                             { "logprobs", nullptr },
                             { "finish_reason", nullptr } } } } };

    return js.dump() + "\n\n";
};
