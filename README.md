# Ripple20 - Payload

This script tests for vulnerabilities in the **Treck TCP/IP stack** by sending a custom payload to the target server. The payload contains the string `"CyRAACS is able to inject payload in the server"`. It then listens for a response from the server to determine if the packets were mishandled.

If the server is vulnerable, it will reply with a response, and the script will print the payload captured in the request in both **Hex** and **ASCII** formats.

## Usage

1. **Run the script** by providing the target server's IP address.
2. The script will send the custom fragmented payload to the server.
3. It will capture and display the server's response to check for mishandling of the packets.

## Example Output

- The output will show the response from the server, including both **Hex** and **ASCII** representations of the captured payload.

## Author

- **@Ransc0rp1on**
