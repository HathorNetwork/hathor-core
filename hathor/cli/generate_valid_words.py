from argparse import ArgumentParser, Namespace


def generate_words(language: str = 'english', count: int = 24) -> str:
    from mnemonic import Mnemonic
    mnemonic = Mnemonic(language)
    return mnemonic.generate(strength=int(count * 10.67))


def create_parser() -> ArgumentParser:
    from hathor.cli.util import create_parser
    parser = create_parser()
    parser.add_argument('--language', help='Words language')
    parser.add_argument('--count', type=int, help='Word count')
    return parser


def execute(args: Namespace) -> None:
    kwargs = {}

    if args.language:
        kwargs['language'] = args.language
    if args.count:
        kwargs['count'] = args.count

    print(generate_words(**kwargs))


def main():
    parser = create_parser()
    args = parser.parse_args()
    execute(args)
