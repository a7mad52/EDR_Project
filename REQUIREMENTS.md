### Requirements

#### Server Side:

1. The server must run on a Linux machine because some functionalities (e.g., `grep`, `apache2`) are Linux-specific.
2. Root privileges are required to start/stop services like Apache2 and to access certain system logs.
3. Python 3+ is required to run the server script.

#### Client Side:

1. Clients can run on either Windows or Linux.
2. Clients must be connected to the same local network as the server to communicate with it.
3. An internet connection is required to fetch restricted sites from the Apache2 server.
4. Python 3+ is required to run the client script.
5. The following Python modules are required:
   - **Scapy**: For packet sniffing and network analysis.
   - **Bs4 (BeautifulSoup)**: For parsing HTML content (e.g., extracting restricted sites).
   - **Lxml**: A dependency for BeautifulSoup to parse HTML efficiently.

### How to Install Client-Side Dependencies

To install the required Python modules on the client side, run the following command:

```bash
pip install scapy beautifulsoup4 lxml
