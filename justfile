# sleuthre justfile

# List available recipes
default:
    @just --list

# Run clippy linter with warnings as errors
lint:
    cargo clippy -- -D warnings

# Format all code in place
format:
    cargo fmt

# Check formatting without modifying files
format-check:
    cargo fmt --check

# Lint and format-check (CI-style)
check: lint format-check

# Build the project
build:
    cargo build

# Run all tests
test:
    cargo test

# Run the GUI
run:
    cargo run -p re-gui

# Build in release mode
release:
    cargo build --release
