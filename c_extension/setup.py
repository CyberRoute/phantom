"""Build configuration for the native arpscanner C extension."""
import os
import sysconfig

from setuptools import setup, Extension  # pylint: disable=import-error

# For macOS, we need to explicitly include libpcap
extra_compile_args = []
extra_link_args = []

if os.uname().sysname == 'Darwin':  # macOS
    extra_compile_args = ['-I/opt/homebrew/include']
    extra_link_args = ['-L/opt/homebrew/lib', '-lpcap']

module = Extension('arpscanner',
                  sources=['arpscanner.c'],
                  include_dirs=[sysconfig.get_path('include')],
                  extra_compile_args=extra_compile_args,
                  extra_link_args=extra_link_args)

setup(
    name='ArpScanner',
    version='1.0',
    ext_modules=[module]
)
