import argparse

from scrutiny import Scrutiny
from scrutiny.settings import __version__

if __name__ == "__main__":

    arg_parser = argparse.ArgumentParser(description='Scrutiny - Log Parser.')
    arg_parser.add_argument('--delete',
        action='store_true',
        default=False,
        dest='delete_rows',
        help="Delete existing rows in the Breakin-attempts and Banned IPs tables.")

    args = arg_parser.parse_args()

    s = Scrutiny()
    if args.delete_rows:
        s.clear_db()
    else:
        s.parse()
