from argparse import ArgumentParser

import configargparse


def create_parser() -> ArgumentParser:
    return configargparse.ArgumentParser(auto_env_var_prefix='hathor_')
