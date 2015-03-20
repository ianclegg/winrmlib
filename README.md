# winrmlib (beta) [![Build Status](https://travis-ci.org/ianclegg/winrmlib.svg?branch=master)](https://travis-ci.org/ianclegg/winrmlib)

## Vision:
A robust, fast and efficient 'first-class' Python Library for Windows Remote Management

- Remote Shell support including stream compression
- Support for all available Authentication Mechanisms
- Support for both protocol and transport level encryption
- Credential Delegation with Kerberos and NTLM (CredSSP)
- Pre-Authentication, TCP connection recycling and TLS session reuse
- Super safe and easy to use API

Known Issues:
- Protocol encryption (GSS API wrap) is not yet implemented, use HTTPS for now
- TCP connection reuse is not implemented
- Subscription has not been tested
- Lowlevel PUT operation not yet implemented
- Only Negotiate (NTLM) and CredSSP are currently available
- XPRESS compression is not available (requires a 'C' implementation due to performance)
- SLDC (Streaming Lossless Data Compresssion) is not implemented

Example:

```python
# construct the Remote Shell on hostname using the supplied credentials
# a connection to the remote host is not made until the 'open' method is called
shell = CommandShell('https://hostname:5986/wsman', 'domain\username', 'password')

# open the remote shell
shell.open()

# run the command: echo 'hello world'
# this is asynchronous, so store the command id to retrieve the status and output later
command_id = shell.run('echo', ['hello world'])

# now receive the output and exit code of the previous command
(stdout, stderr, exit_code) = shell.receive(command_id)

# display 'hello' world
print stdout

# close the shell on the remote host
shell.close()
```


