# Proxy Server 

This is a simple proxy server implemented in C that includes a prefetching mechanism. The proxy server intercepts HTTP requests, caches the responses, and also prefetches links found in HTML content.

## Features

- **Proxy Server**: Handles HTTP requests and forwards them to the target server.
- **Caching**: Stores cached responses to improve response time for subsequent requests.
- **Prefetching**: Scans HTML content for links and prefetches them to improve user experience.
- **Blacklisting**: Blocks blacklisted requests given in a txt file.

## Usage

1. **Compilation**: Compile the program using a C compiler (e.g., `gcc`).
   ```bash
   make
   ```

2. **Execution**: Run the compiled binary, specifying the port number.
   ```bash
   ./proxy <port> [timeout]
   ```
   - `<port>`: Port number for the proxy server.
   - `[timeout]`: Optional timeout value for cache expiration (default is 0 seconds).
   or make run (need to change timeout in Makefile if needed)

3. **Accessing through Browser**: Configure your browser to use the proxy server with the specified port.

## Configuration

- **Blacklist**: You can define a blacklist in the `blacklist` file to block certain hostnames or IPs.

## File Structure

- **cache/**: Directory to store cached files.
- **blacklist**: File containing blacklisted hostnames or IPs.

## License

This project is licensed under the [MIT License](LICENSE).

## Acknowledgments

- The program uses the [OpenSSL](https://www.openssl.org/) library for MD5 hashing.
