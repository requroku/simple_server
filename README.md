# Simple Server

> Simple HTTP / HTTPS server with upload, download & logging functionality.


To **download** any file relative to the server root directory via GET request, path to file **must be prepended** with one of the following prefixes: `['/d/', '/download/']`. For example: `https://127.0.0.1/d/myfile.txt`.

To **upload** file(s) make a POST request to one of the following endpoints: `['/u', '/up', '/upload']` (if you try to upload a file to another handler, it won't work). Grouping of uploaded files in separate directories is done using URL parameter `dir_name`.

If `--no-tls` and `--cert-dir` flags are not specified, then generates random self-signed certificate and private key to provide TLS ecryption (files stored in `data/cert`).  
If `--cert-dir` is specified, then searches for files `full_certificate_chain.pem` and  `private_key.pem` in specified directory to enable TLS.

Log files are created in `data/log` directory in the following format: `simple_server_YYYYMMDDhhmm.log`.


Directory structure:
```log
/data
    ├── cert
    ├── log
    └── upload
        ├── <DIR_NAME>
        │   └── file1.txt
        │   └── file2.txt
        └── file3.txt
```

Adjust if necessary ;)


## Usage
```
usage: simple_server.py [-h] [--bind ADDRESS] [--port PORT] [-o OUT_DIR]
                        [--cert-dir CERT_DIR | --no-tls]

Simple HTTP / HTTPS server with upload, download & logging functionality. 

options:
  -h, --help            show this help message and exit
  --bind ADDRESS, -b ADDRESS
                        IP address to run server on (default: all interfaces)  
  --port PORT, -p PORT  port to run server on (default: 443)
  -o OUT_DIR            output directory for logs and upload data (default:    
                        "data")
  --cert-dir CERT_DIR   directory containing "full_certificate_chain.pem" and  
                        "private_key.pem" files. If not specified, generates   
                        random self-signed certificate.
  --no-tls              do NOT use TLS encryption, if (for any reason) you     
                        need HTTP server
```


## Examples
### Download
Download single file from server root directory and save to a file named as the remote file: 
```sh
curl --insecure -O "https://127.0.0.1/download/file_to_download.txt"
```

### Upload
Upload single file:
```sh
curl --insecure -X POST -F filename=@"file3.txt" "https://127.0.0.1/upload"
```

Upload several files in separate directory "`my_files`":
```sh
curl --insecure -X POST -F filename=@"file1.txt" -F filename=@"file2.txt" "https://127.0.0.1/upload?dir_name=my_files"
```
