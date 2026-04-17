# Student project: HMAC Voter Authentication System Makefile
# Compile with: gcc server.c -lssl -lcrypto -o server

CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -O2
LIBS = -lssl -lcrypto -lpthread
TARGET = server
SOURCE = server.c

# Default target
all: $(TARGET)

# Compile the server
$(TARGET): $(SOURCE)
	$(CC) $(CFLAGS) -o $(TARGET) $(SOURCE) $(LIBS)
	@echo "✓ Server compiled successfully"
	@echo "Usage:"
	@echo "  ./server sender    # Run in sender mode"
	@echo "  ./server receiver  # Run in receiver mode"

# Clean build artifacts
clean:
	rm -f $(TARGET)
	@echo "✓ Cleaned build artifacts"

# Install dependencies (Ubuntu/Debian)
install-deps:
	@echo "Installing dependencies..."
	sudo apt-get update
	sudo apt-get install -y libssl-dev build-essential
	@echo "✓ Dependencies installed"

# Install dependencies (CentOS/RHEL/Fedora)
install-deps-rhel:
	@echo "Installing dependencies..."
	sudo yum install -y openssl-devel gcc make
	@echo "✓ Dependencies installed"

# Run sender mode
run-sender: $(TARGET)
	./$(TARGET) sender

# Run receiver mode  
run-receiver: $(TARGET)
	./$(TARGET) receiver

# Test compilation
test: $(TARGET)
	@echo "✓ Compilation test passed"

# Debug build
debug: CFLAGS += -g -DDEBUG
debug: $(TARGET)
	@echo "✓ Debug build created"

# Help target
help:
	@echo "HMAC Voter Authentication System - Makefile Targets:"
	@echo ""
	@echo "  all              - Build the server (default)"
	@echo "  clean            - Remove build artifacts"
	@echo "  test             - Test compilation"
	@echo "  debug            - Build with debug symbols"
	@echo "  run-sender       - Build and run in sender mode"
	@echo "  run-receiver     - Build and run in receiver mode"
	@echo "  install-deps     - Install dependencies (Ubuntu/Debian)"
	@echo "  install-deps-rhel- Install dependencies (RHEL/CentOS/Fedora)"
	@echo "  help             - Show this help message"
	@echo ""
	@echo "Usage examples:"
	@echo "  make              # Build the server"
	@echo "  make run-sender   # Build and run sender"
	@echo "  make run-receiver # Build and run receiver"
	@echo "  make clean        # Clean up"

# Create distribution package
dist: clean
	@echo "Creating distribution package..."
	tar -czf hmac_voter_auth.tar.gz ../hmac_voter_auth/
	@echo "✓ Distribution package created: hmac_voter_auth.tar.gz"

# Check if required libraries are available
check-deps:
	@echo "Checking dependencies..."
	@pkg-config --exists openssl && echo "✓ OpenSSL found" || echo "✗ OpenSSL not found"
	@$(CC) --version > /dev/null 2>&1 && echo "✓ GCC found" || echo "✗ GCC not found"

# Format code (requires clang-format)
format:
	@if command -v clang-format >/dev/null 2>&1; then \
		clang-format -i $(SOURCE); \
		echo "✓ Code formatted"; \
	else \
		echo "✗ clang-format not found. Install with: sudo apt-get install clang-format"; \
	fi

# Static analysis (requires cppcheck)
analyze:
	@if command -v cppcheck >/dev/null 2>&1; then \
		cppcheck --enable=all --std=c99 $(SOURCE); \
	else \
		echo "✗ cppcheck not found. Install with: sudo apt-get install cppcheck"; \
	fi

.PHONY: all clean test debug run-sender run-receiver install-deps install-deps-rhel help dist check-deps format analyze
