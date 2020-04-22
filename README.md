# HTTP Basic Authentication Honeypot

A simple honeypot written in C that logs HTTP basic authentication attempts. Requires libmicrohttpd.

## Build

#### Install Dependencies

```
~$ sudo apt-get install build-essential openssl libmicrohttpd-dev 
```

(https://www.gnu.org/software/libmicrohttpd/)

#### Generate SSL Certificate

```
~$ openssl genrsa -out localhost.key 1024
~$ openssl req -days 365 -out localhost.pem -new -x509 -key localhost.key
```

#### Compile

```
~$ gcc -o http-basic-auth-honeypot http-basic-auth-honeypot.c -lmicrohttpd
```

## Run

#### Usage

```
~$ ./http-basic-auth-honeypot <port> <key> <cert>
```

#### Example

```
~$ ./http-basic-auth-honeypot 8080 localhost.key localhost.pem
```

Enter any key to exit the program.

## Logs

**auth.log**

Format `[Date-Time] Client IP "User-Agent" user:pass`

Example `[Tue Apr 17 23:59:51 2020] 127.0.0.1 "Wget/1.19.4 (linux-gnu)" john:smith`
