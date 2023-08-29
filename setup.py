from setuptools import setup, find_packages

from pathlib import Path
this_directory = Path(__file__).parent
long_description = (this_directory / "README.md").read_text()

setup(
    name='dotnetfile',
    version='0.2.4',
    author='Bob Jung, Yaron Samuel, Dominik Reichel',
    description='Library to parse the CLR header of .NET assemblies',
    long_description=long_description,
    long_description_content_type='text/markdown',
    packages=find_packages(),
    package_dir={'dotnetfile': 'dotnetfile'},
    install_requires=[
        'pefile'
    ],
    python_requires='>=3.7'
)
