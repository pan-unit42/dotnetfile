from setuptools import setup, find_packages

setup(
    name='dotnetfile',
    version='0.1.0',
    author='Bob Jung, Yaron Samuel, Dominik Reichel',
    description='Library to parse the CLR header of .NET assemblies',
    packages=find_packages(),
    package_dir={'dotnetfile': 'dotnetfile'},
    install_requires=[
        'pefile'
    ],
    python_requires='>=3.7'
)
