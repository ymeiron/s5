SciNet Super Simple Secrets Server
==================================

S⁵ is a minimalist key manager. The server will ask for a secret (e.g. a password) and store it in memory until the client queries and receives it. The specific use case is a queued job in a high performance computing (HPC) environment that needs to use encryption, but the encryption key should not be passed in plaintext when the job is submitted.

When the server starts, it generates a random 96-byte token. The high 48 bytes are used to identify the client, and the low 48 bytes are used as a one-time pad. The client and server communicate via HTTP, despite not using transport layer security, the encrypted response provides resilience to a man-in-the-middle attack.

By default, the token is stored along with the host and port information in the user's home directory. This makes it automatically accessible to a client process running on a compute node that shares a filesystem with the node (e.g. a login node) where the server is running. If the client is not on a shared filesystem, the connection information (including the token) can be specified as command line arguments or the client file can be manually copied.

The server shuts down by default once a successful query is made, but this behaviour can be adjusted with the `--success-max` command line argument.

Usage
-----

Start the server with `s5server` and type in the secret. The connection information is saved to `~/.s5client.json` by default. If the client will be running on a node that shares a filesystem and can reach the server's node by its hostname, then nothing needs to be done. Run the client with `s5client` and receive the secret into standard output.