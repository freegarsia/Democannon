#pragma once

#include <spdlog/spdlog.h>
#include <spdlog/sinks/basic_file_sink.h>
#include <ctime>

extern std::shared_ptr<spdlog::logger> Logger;

void cannonLogger_warning(const char *);
void cannonLogger_error(const char*);
void cannonLogger_info(const char*);
