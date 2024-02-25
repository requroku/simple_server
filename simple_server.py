#!/usr/bin/env python3
"""
Simple HTTP / HTTPS server with upload, download & logging functionality.
"""
import re
import ssl
import uuid
import socket
import logging
import argparse
from pathlib import Path
from functools import partial
from urllib.parse import urlparse, parse_qs
from datetime import datetime, timedelta
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID


def sanitize_filename(filename: str) -> str:
    """
    Replaces all forbidden chars with '' and removes unnecessary whitespaces.
    If, after sanitization, the given filename is empty, the function will return 'file_[UUID][ext]'.

    :param filename: filename to be sanitized
    :return: sanitized filename
    """
    chars = ['\\', '/', ':', '*', '?', '"', '<', '>', '|']

    filename = filename.translate({ord(x): '' for x in chars}).strip()
    name = re.sub(r'\.[^.]+$', '', filename)
    extension = re.search(r'(\.[^.]+$)', filename)
    extension = extension.group(1) if extension else ''

    return filename if name else f'file_{uuid.uuid4().hex}{extension}'


def save_file(filename: str, file_data: bytes) -> tuple[bool, str]:
    """
    Save file to filesystem.
    Rewrites a file in dir with the same name, if it already exists.
    """
    try:
        with open(f'{filename}', 'wb') as file:
            file.write(file_data)

    except Exception as err:
        return False, f'save_file(): {err}. Couldn\'t save "{filename}".'

    return True, filename


class HTTPRequestHandler(SimpleHTTPRequestHandler):
    """
    HTTP request handler with upload & download functionality.
    This class is derived from SimpleHTTPRequestHandler with small tweaks
    to add upload, download and logging functionality.
    """
    # Hide server information. You know, for security
    sys_version = ''
    server_version = 'nginx'

    def __init__(self, upload_dir: Path, *args, **kwargs) -> None:
        self.upload_dir = upload_dir
        # SimpleHTTPRequestHandler calls do_METHOD **inside** __init__ !!!
        # So we have to call super().__init__ after setting attributes.
        super().__init__(*args, **kwargs)

    def _set_response(self, response: str) -> None:
        """Set status code, headers and send response."""
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(response.encode())

    def _log_request(self) -> None:
        """Log the request and its data to a file."""
        log_message = ''

        # If header is present and not zero
        if self.headers['Content-Length']:
            # Get size of data
            content_length = int(self.headers['Content-Length'])

            # Do not log request body, if it's too large or content_length is incorrect
            if content_length > 0 and content_length < 1000000:
                # Get the data itself (in bytes)
                post_data = self.rfile.read(content_length)

                logging.info(
                    f'\n{self.command} {self.path} {self.request_version}\n'
                    f'{self.headers}{post_data.decode()}\n\n')
                return

            log_message = f'attached file(s) size is about {content_length} bytes|'

        logging.info(
            f'{log_message}\n{self.command} {self.path} {self.request_version}\n'
            f'{self.headers}')

    def _handle_upload(self) -> tuple[bool, list[str]]:
        """
        Handle file upload. Reads entire HTTP Request body and dumps it into a file.
        Returns (result, message). Where message contains error description,
        otherwise - successfully uploaded filenames.
        """
        try:
            # extract boundary from headers
            boundary = re.search(f'boundary=([^;]+)',
                                 self.headers['Content-Type']).group(1)

            # read all bytes (headers included)
            # 'readlines()' hangs the script because it needs the EOF character to stop,
            # even if you specify how many bytes to read.
            # 'file.read(nbytes).splitlines(True)' does the trick because 'read()' reads 'nbytes' bytes
            # and 'splitlines(True)' splits the file into lines and retains the newline character.
            data = self.rfile.read(int(
                self.headers['Content-Length'])).splitlines(True)

            # find all filenames
            filenames = re.findall(f'{boundary}.+?filename="(.+?)"', str(data))

            if not filenames:
                return False, 'couldn\'t find file name(s).'

            filenames = [sanitize_filename(filename) for filename in filenames]

            # find all boundary occurrences in data
            boundary_indices = list((i for i, line in enumerate(data)
                                     if re.search(boundary, str(line))))

            parsed_url = urlparse(self.path)
            dir_name = parse_qs(parsed_url.query).get('dir_name')

            # If there is a "dir_name" parameter in request, then
            # get its value and create separate dir to group uploaded files.
            if dir_name:
                self.upload_dir = Path.joinpath(self.upload_dir, dir_name[0])
                self.upload_dir.mkdir(parents=True, exist_ok=True)

            # save file(s)
            for i, filename in enumerate(filenames):

                full_filename = Path.joinpath(self.upload_dir, filename)

                if full_filename.is_file():
                    print(
                        f'[!] "{full_filename}" already exists! Overwriting.')
                    logging.warning(
                        f'"{full_filename}" already exists! Overwriting.')

                # remove file headers
                file_data = data[(boundary_indices[i] + 4):boundary_indices[i +
                                                                            1]]

                # join list of bytes into bytestring
                file_data = b''.join(file_data)

                result, message = save_file(full_filename, file_data)

                if result:
                    logging.info(f'"{message}" successfully uploaded!')
                else:
                    print(f'[-] error: {message}')
                    logging.error(f'save_file(): {message}')

        except Exception as err:
            return False, err

        return True, filenames

    def do_HEAD(self) -> None:
        """Serve a HEAD request."""
        self._log_request()
        response = f'HEAD_response'
        self._set_response(response)

    def do_GET(self) -> None:
        """Serve a GET request."""
        self._log_request()

        DOWNLOAD_PATH_PREFIXES = ['d', 'download']

        url_path_first = urlparse(self.path).path.split('/')[1]

        # If request is not for file download, then serve as usual
        if url_path_first not in DOWNLOAD_PATH_PREFIXES:
            response = f'GET_response'
            self._set_response(response)
        else:
            # For SimpleHTTPRequestHandler dir listing, file mapping and download logic
            # to work we have to remove DOWNLOAD_PATH prefix from self.path,
            # then call original do_GET.
            self.path = urlparse(self.path).path.split(url_path_first, 1)[1]
            return SimpleHTTPRequestHandler.do_GET(self)

    def do_POST(self) -> None:
        """Serve a POST request."""
        UPLOAD_PATH_PREFIXES = ['u', 'up', 'upload']
        # If not file upload, then serve as usual
        if urlparse(self.path).path.split('/')[1] not in UPLOAD_PATH_PREFIXES:
            # If an HTTP request has a body (like a POST request generated by a form),
            # you have to read (consume) it in your application. If you do not do this,
            # the communication socket with your webserver may be clobbered.
            # Thus, files are uploaded only by URLs above.
            self._log_request()
            response = f'POST_response'
        else:
            result, message = self._handle_upload()
            response = 'successful upload'

            if not result:
                response = 'error'
                print(
                    f'[-] error: self._handle_upload(): {message}. Caused by: '
                    f'"POST {self.path} {self.request_version}"')
                logging.error(
                    f'self._handle_upload(): {message}|\n'
                    f'POST {self.path} {self.request_version}\n{self.headers}')

        self._set_response(response)


def gen_self_signed_cert() -> tuple[bytes, bytes]:
    """
    Generate a random self-signed certificate and private key using "cryptography".
    Returns (cert, key) as ASCII PEM strings (in bytes).
    """
    one_day = timedelta(1, 0, 0)
    private_key = rsa.generate_private_key(public_exponent=65537,
                                           key_size=2048,
                                           backend=default_backend())
    public_key = private_key.public_key()

    builder = x509.CertificateBuilder()
    builder = builder.subject_name(
        x509.Name(
            [x509.NameAttribute(NameOID.COMMON_NAME, socket.gethostname())]))
    builder = builder.issuer_name(
        x509.Name(
            [x509.NameAttribute(NameOID.COMMON_NAME, socket.gethostname())]))
    builder = builder.not_valid_before(datetime.today() - one_day)
    builder = builder.not_valid_after(datetime.today() + (one_day * 365 * 5))
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.public_key(public_key)
    builder = builder.add_extension(x509.SubjectAlternativeName([
        x509.DNSName(socket.gethostname()),
        x509.DNSName(f'*.{socket.gethostname()}'),
        x509.DNSName('localhost'),
        x509.DNSName('*.localhost'),
    ]),
                                    critical=False)
    builder = builder.add_extension(x509.BasicConstraints(ca=False,
                                                          path_length=None),
                                    critical=True)

    certificate = builder.sign(private_key=private_key,
                               algorithm=hashes.SHA256(),
                               backend=default_backend())

    return (certificate.public_bytes(serialization.Encoding.PEM),
            private_key.private_bytes(serialization.Encoding.PEM,
                                      serialization.PrivateFormat.PKCS8,
                                      serialization.NoEncryption()))


def run_server(args: argparse.Namespace) -> None:
    try:
        server_address = (args.bind, args.port)

        # "partially apply" the first N arguments to the HTTPRequestHandler
        handler = partial(HTTPRequestHandler, args.upload_dir)
        # ... then pass it to HTTPServer as normal
        httpd = ThreadingHTTPServer(server_address, handler)

        if not args.no_tls:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

            if args.cert_dir:
                logging.debug(f'certificate directory: "{args.cert_dir}"')
                context.load_cert_chain(
                    Path.joinpath(args.cert_dir, 'full_certificate_chain.pem'),
                    Path.joinpath(args.cert_dir, 'private_key.pem'))
            else:
                print(
                    f'[*] TLS certificate and private key are not provided. Generating...'
                )
                logging.debug(
                    f'TLS certificate and private key are not provided. Generating...'
                )
                server_certificate, private_key = gen_self_signed_cert()

                # Because of the compatibility on the lower level load_cert_chain()
                # accepts ONLY paths to files on filesystem. So we have to
                # generate cert and key, then save them to filesystem.
                cert_dir = Path.joinpath(args.out_dir, 'cert')
                cert_dir.mkdir(parents=True, exist_ok=True)

                cert_file_path = Path.joinpath(cert_dir,
                                               'server_certificate.pem')
                priv_key_file_path = Path.joinpath(cert_dir, 'private_key.pem')

                save_file(cert_file_path, server_certificate)
                save_file(priv_key_file_path, private_key)

                context.load_cert_chain(cert_file_path, priv_key_file_path)

            httpd.socket = context.wrap_socket(httpd.socket, server_side=True)

        httpd.serve_forever()

    except KeyboardInterrupt:
        print('\n[*] Keyboard interrupt received, shutting down the httpd...')

    finally:
        httpd.server_close()


def configure_logging(out_dir: Path) -> None:
    """Configure everything related to logging."""
    logfile_dir = Path.joinpath(out_dir, 'log')
    logfile_dir.mkdir(parents=True, exist_ok=True)
    logfile_prefix = 'simple_server_'
    logfile_filename = Path.joinpath(
        logfile_dir,
        datetime.now().strftime(f'{logfile_prefix}%Y%m%d%H%M.log'))

    logging.basicConfig(format='%(asctime)s|%(levelname)s|%(message)s',
                        filename=logfile_filename,
                        level=logging.INFO)


def configure(args: argparse.Namespace) -> None:
    """Initialize different parameters, create dirs."""
    # Specify output dir
    if args.out_dir is None:
        args.out_dir = Path.joinpath(Path.cwd(), 'data')
    else:
        args.out_dir = Path.joinpath(Path.cwd(), args.out_dir)

    # Specify certificate dir
    if not args.no_tls and args.cert_dir is not None:
        args.cert_dir = Path.joinpath(Path.cwd(), args.cert_dir)

    # Create dir to store uploaded files
    args.upload_dir = Path.joinpath(args.out_dir, 'upload')
    args.upload_dir.mkdir(parents=True, exist_ok=True)

    # Configure logging
    configure_logging(args.out_dir)


def parse_args() -> argparse.Namespace:
    """Process CLI arguments."""
    parser = argparse.ArgumentParser(
        description=
        'Simple HTTP / HTTPS server with upload, download & logging functionality.'
    )

    parser.add_argument('--bind',
                        '-b',
                        metavar='ADDRESS',
                        help='IP address to run server on '
                        '(default: all interfaces)',
                        default='0.0.0.0')

    parser.add_argument('--port',
                        '-p',
                        help='port to run server on (default: %(default)d)',
                        default=443,
                        type=int)

    parser.add_argument('-o',
                        dest='out_dir',
                        help='output directory for logs and upload data '
                        '(default: "data")')

    use_tls_group = parser.add_mutually_exclusive_group()

    use_tls_group.add_argument(
        '--cert-dir',
        help=
        'directory containing "full_certificate_chain.pem" and "private_key.pem" files. '
        'If not specified, generates random self-signed certificate.')

    use_tls_group.add_argument(
        '--no-tls',
        help=
        'do NOT use TLS encryption, if (for any reason) you need HTTP server',
        action='store_true')

    return parser.parse_args()


def main() -> None:
    args = parse_args()

    configure(args)

    server_url = f'{"http" if args.no_tls else "https"}://{args.bind}:{args.port}'

    print(f'[*] httpd started on {server_url}')
    logging.info(f'httpd started on {server_url}')

    run_server(args)

    print('[*] httpd stopped')
    logging.info('httpd stopped')


if __name__ == '__main__':
    main()
