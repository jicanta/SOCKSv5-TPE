# Makefile para servidor proxy SOCKSv5
# =====================================

# Compilador y flags
CC = gcc
CFLAGS = -Wall -Wextra -pedantic -std=c11 -g -O2 -D_POSIX_C_SOURCE=200112L
CFLAGS += $(CFLAGS_EXTRA)
LDFLAGS = -lpthread

# Directorios
SRC_DIR = src
SERVER_DIR = $(SRC_DIR)/server
SHARED_DIR = $(SRC_DIR)/shared
TESTS_DIR = $(SRC_DIR)/tests
BUILD_DIR = build
OBJ_DIR = $(BUILD_DIR)/obj
BIN_DIR = $(BUILD_DIR)/bin

# Includes
INCLUDES = -I. \
           -Iinclude \
           -I$(SRC_DIR)/include \
           -I$(SERVER_DIR)/parser/include \
           -I$(SERVER_DIR)/states/include \
           -I$(SERVER_DIR)/utils/include \
           -I$(SHARED_DIR)/include \
           -I$(TESTS_DIR)/include

# Archivos fuente del servidor
SERVER_SOURCES = $(SRC_DIR)/main.c \
                 $(SRC_DIR)/socks5nio.c \
                 $(SRC_DIR)/socks5_hello.c \
                 $(SRC_DIR)/socks5_auth.c \
                 $(SRC_DIR)/socks5_request.c \
                 $(SRC_DIR)/socks5_copy.c \
				 $(SRC_DIR)/hello_parser.c \
                 $(SRC_DIR)/metrics.c \
                 $(SRC_DIR)/management.c \
                 $(SERVER_DIR)/parser/parser.c \
                 $(SERVER_DIR)/parser/parser_utils.c \
                 $(SERVER_DIR)/states/stm.c \
                 $(SERVER_DIR)/utils/buffer.c \
                 $(SERVER_DIR)/utils/netutils.c \
                 $(SERVER_DIR)/utils/selector.c \
                 $(SHARED_DIR)/args.c

# Archivos objeto
SERVER_OBJECTS = $(patsubst %.c,$(OBJ_DIR)/%.o,$(notdir $(SERVER_SOURCES)))

# Ejecutable principal
TARGET = $(BIN_DIR)/socks5d

# Tests
TEST_SOURCES = $(wildcard $(TESTS_DIR)/*_test.c)
TEST_TARGETS = $(patsubst $(TESTS_DIR)/%_test.c,$(BIN_DIR)/%_test,$(TEST_SOURCES))
TEST_LDFLAGS = $(LDFLAGS) -lcheck -lm -lsubunit

# VPATH para encontrar los archivos fuente
VPATH = .:$(SRC_DIR):$(SERVER_DIR)/parser:$(SERVER_DIR)/states:$(SERVER_DIR)/utils:$(SHARED_DIR)

# Colores para output
RED = \033[0;31m
GREEN = \033[0;32m
YELLOW = \033[0;33m
NC = \033[0m

# =====================================
# Targets principales
# =====================================

.PHONY: all clean test run help dirs

all: dirs $(TARGET)
	@echo "$(GREEN)Build completado: $(TARGET)$(NC)"

# Crear directorios necesarios
dirs:
	@mkdir -p $(OBJ_DIR)
	@mkdir -p $(BIN_DIR)

# Compilar el ejecutable principal
$(TARGET): $(SERVER_OBJECTS)
	@echo "$(YELLOW)Linking $(TARGET)...$(NC)"
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $^ $(LDFLAGS)

# Regla genérica para compilar archivos .c a .o
$(OBJ_DIR)/%.o: %.c
	@echo "$(YELLOW)Compilando $<...$(NC)"
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

# =====================================
# Tests
# =====================================

test: dirs $(TEST_TARGETS)
	@echo "$(GREEN)Ejecutando tests...$(NC)"
	@for test in $(TEST_TARGETS); do \
		echo "$(YELLOW)Running $$test$(NC)"; \
		$$test; \
	done

$(BIN_DIR)/buffer_test: $(TESTS_DIR)/buffer_test.c $(SERVER_DIR)/utils/buffer.c
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $< $(TEST_LDFLAGS)

$(BIN_DIR)/netutils_test: $(TESTS_DIR)/netutils_test.c $(SERVER_DIR)/utils/netutils.c
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $< $(TEST_LDFLAGS)

$(BIN_DIR)/selector_test: $(TESTS_DIR)/selector_test.c $(SERVER_DIR)/utils/selector.c
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $< $(TEST_LDFLAGS)

$(BIN_DIR)/parser_test: $(TESTS_DIR)/parser_test.c $(SERVER_DIR)/parser/parser.c
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $< $(TEST_LDFLAGS)

$(BIN_DIR)/parser_utils_test: $(TESTS_DIR)/parser_utils_test.c $(SERVER_DIR)/parser/parser_utils.c
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $< $(TEST_LDFLAGS)

$(BIN_DIR)/stm_test: $(TESTS_DIR)/stm_test.c $(SERVER_DIR)/states/stm.c
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $< $(TEST_LDFLAGS)

# Compile the test unit object
build/obj/test_sock5_unit.o: src/tests/test_sock5_unit.c
	@mkdir -p build/obj
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

# Link and Run the Unit Tests
test_unit: $(SERVER_OBJECTS) build/obj/test_sock5_unit.o
	$(CC) $(CFLAGS) $(filter-out build/obj/main.o build/obj/socks5nio.o build/obj/selector.o, $(SERVER_OBJECTS)) build/obj/test_sock5_unit.o -o test_runner
	./test_runner

.PHONY: test_unit

# =====================================
# Utilidades
# =====================================

# Ejecutar el servidor
run: all
	@echo "$(GREEN)Iniciando echo_server...$(NC)"
	$(TARGET)

# Ejecutar con puerto específico
run-port: all
	@echo "$(GREEN)Iniciando echo_server en puerto $(PORT)...$(NC)"
	$(TARGET) $(PORT)

# Limpiar archivos generados
clean:
	@echo "$(YELLOW)Limpiando archivos generados...$(NC)"
	rm -rf $(BUILD_DIR)
	@echo "$(GREEN)Limpieza completada$(NC)"

# Rebuild completo
rebuild: clean all

# Información de debug
debug: CFLAGS += -DDEBUG -g3 -O0
debug: clean all

# Build de release (optimizado)
release: CFLAGS = -Wall -Wextra -pedantic -std=c11 -O3 -DNDEBUG -D_POSIX_C_SOURCE=200112L
release: clean all

# Mostrar ayuda
help:
	@echo "Makefile para servidor proxy SOCKSv5"
	@echo ""
	@echo "Targets disponibles:"
	@echo "  all       - Compila el servidor (default)"
	@echo "  clean     - Elimina archivos generados"
	@echo "  rebuild   - Limpia y recompila todo"
	@echo "  test      - Compila y ejecuta los tests"
	@echo "  run       - Compila y ejecuta el servidor (puerto 1080)"
	@echo "  run-port  - Ejecuta en puerto específico (make run-port PORT=8080)"
	@echo "  debug     - Compila con símbolos de debug"
	@echo "  release   - Compila versión optimizada"
	@echo "  help      - Muestra esta ayuda"
	@echo ""
	@echo "Ejemplo de uso:"
	@echo "  make            # Compila el proyecto"
	@echo "  make run        # Ejecuta el servidor"
	@echo "  make test       # Ejecuta los tests"
