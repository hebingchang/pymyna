from myna.core.reader import MyNumberCardReader
import argparse


def main():
    parser = argparse.ArgumentParser(
        description='My Number Card cli!',
        formatter_class=argparse.RawTextHelpFormatter)
    subparsers = parser.add_subparsers(dest='ap', required=True)

    jpki_parser = subparsers.add_parser('jpki', help='JPKI AP related commands.')
    jpki_actions = jpki_parser.add_subparsers(dest='action', required=True)
    jpki_sign = jpki_actions.add_parser('sign', help='Compute signature for given file.')
    jpki_sign.add_argument('file', type=str,
                           help='Path of the file to be signed')
    jpki_verify = jpki_actions.add_parser('verify', help='Verify signature for given file.')
    jpki_verify.add_argument('file', type=str,
                             help='Path of the file to be verified')

    text_parser = subparsers.add_parser('text', help='Text AP related commands.')
    visual_parser = subparsers.add_parser('visual', help='Visual AP related commands.')

    args = parser.parse_args()

    # TODO
    print(args)


if __name__ == "__main__":
    main()
