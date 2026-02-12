from setuptools import setup, find_packages

from pathlib import Path
this_directory = Path(__file__).parent
long_description = (this_directory / "README.md").read_text()

setup(
    name='dotnetfile',
    version='0.2.10',
    author='Bob Jung, Yaron Samuel, Dominik Reichel',
    description='Library to parse the CLR header of .NET assemblies',
    packages=find_packages(),
    package_dir={'dotnetfile': 'dotnetfile'},
    install_requires=[
        'pefile',
        'dncil'
    ],
    entry_points={
        'console_scripts': [
            'dotnetfile_dump=tools.dotnetfile_dump:main',
            'dotnetfile_disassemble=tools.dotnetfile_disassemble:main'
        ]
    },
    python_requires='>=3.7'
)
