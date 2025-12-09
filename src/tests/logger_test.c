#include <stdio.h>
#include <unistd.h>
#include "logger.h"

int main(void) {
    printf("==========================================\n");
    printf("       TESTING LOGGER LEVELS             \n");
    printf("==========================================\n\n");

    // Test DEBUG Level (should show everything)
    printf("--- Initializing with LOG_DEBUG ---\n");
    logger_init(NULL, LOG_DEBUG);
    LOG_DEBUG("DEBUG message: Visible [OK]\n");
    LOG_INFO("INFO message:  Visible [OK]\n");
    LOG_WARNING("WARN message:  Visible [OK]\n");
    LOG_ERROR("ERROR message: Visible [OK]\n");
    logger_close();
    printf("\n");

    // Test INFO Level
    printf("--- Initializing with LOG_INFO ---\n");
    logger_init(NULL, LOG_INFO);
    LOG_DEBUG("DEBUG message: Hidden  [FAIL if visible]\n");
    LOG_INFO("INFO message:  Visible [OK]\n");
    LOG_WARNING("WARN message:  Visible [OK]\n");
    LOG_ERROR("ERROR message: Visible [OK]\n");
    logger_close();
    printf("\n");

    // Test WARNING Level
    printf("--- Initializing with LOG_WARNING ---\n");
    logger_init(NULL, LOG_WARNING);
    LOG_DEBUG("DEBUG message: Hidden  [FAIL if visible]\n");
    LOG_INFO("INFO message:  Hidden  [FAIL if visible]\n");
    LOG_WARNING("WARN message:  Visible [OK]\n");
    LOG_ERROR("ERROR message: Visible [OK]\n");
    logger_close();
    printf("\n");

    // Test ERROR Level
    printf("--- Initializing with LOG_ERROR ---\n");
    logger_init(NULL, LOG_ERROR);
    LOG_DEBUG("DEBUG message: Hidden  [FAIL if visible]\n");
    LOG_INFO("INFO message:  Hidden  [FAIL if visible]\n");
    LOG_WARNING("WARN message:  Hidden  [FAIL if visible]\n");
    LOG_ERROR("ERROR message: Visible [OK]\n");
    logger_close();
    printf("\n");

    return 0;
}
