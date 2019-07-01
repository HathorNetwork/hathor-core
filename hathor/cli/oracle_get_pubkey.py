import base64


def main():
    from hathor.cli.util import create_parser
    from hathor.crypto.util import get_hash160, get_private_key_from_bytes, get_public_key_bytes_compressed

    parser = create_parser()

    parser.add_argument('filepath', help='Get public key hash given the private key file')
    args = parser.parse_args()

    with open(args.filepath, 'r') as key_file:
        private_key_bytes = base64.b64decode(key_file.read())
    private_key = get_private_key_from_bytes(private_key_bytes)
    public_key_bytes = get_public_key_bytes_compressed(private_key.public_key())
    print('base64:', base64.b64encode(public_key_bytes).decode('utf-8'))
    print('hash base64:', base64.b64encode(get_hash160(public_key_bytes)).decode('utf-8'))
