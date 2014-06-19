import argparse

from scrutiny import Scrutiny
from scrutiny.settings import __version__

if __name__ == "__main__":
    s = Scrutiny()
    s.parse()
