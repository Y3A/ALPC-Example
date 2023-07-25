# ALPC-Example
ALPC Code Example

### Scenario

Implement an ALPC server that **checks for a secret** during the connect request, and rejects the request if the secret is not satisfied. If the connection is successful, the server will **expect a file handle** from the client and **log a message** to the file.

Implement an ALPC client that passes the secret check, opens a file handle and shares it with the server.

More about ALPC at https://y3a.github.io/2023/07/25/alpc-workings/
