# dotnetfile

`dotnetfile` is a Common Language Runtime (CLR) header parser library for Windows .NET files built in Python. The CLR header is present in every Windows .NET assembly beside the Portable Executable (PE) header. It stores a plethora of metadata information for the managed part of the file.

`dotnetfile` is in a way the equivalent of `pefile` but for .NET samples.

The library provides an easy-to-use API, but also tries to contribute new methods to improve file detection. This includes the MemberRef hash (experimental) and the original and a modified version of TypeRef hash.

The aim of this project is to give malware analysts and threat hunters a tool to easily pull out information from the CLR header. You don't need to be an expert in the CLR header and get lost in its specification to use this library. By using the API, you'll also learn how the header is structured and hopefully get a better understanding of this file type in general.

## Installation

`dotnetfile` requires Python >= 3.7 and [`pefile`](https://github.com/erocarrera/pefile).

### PyPI

You can easily install `dotnetfile` with pip:

```pip install dotnetfile```

### Local setup

To install `dotnetfile` as a module, please use the provided `setup.py` file. This can be done with the help of Python:  

```python3 setup.py install```

## Usage

To use `dotnetfile`, all you have to do is to import the module and create an instance of the class `DotNetPE` with the .NET assembly path as a parameter. A minimal example that prints out the number of streams of an assembly is shown below:

```python #
# Import class DotNetPE from module dotnetfile
from dotnetfile import DotNetPE

# Define the file path of your assembly
dotnet_file_path = '/Users/<username>/my_dotnet_assembly.exe'

# Create an instance of DotNetPE with the file path as a parameter
dotnet_file = DotNetPE(dotnet_file_path)

# Print out the number of streams of the assembly
print(f'Number of streams: {dotnet_file.get_number_of_streams()}')
```

You are invited to explore the example scripts: https://github.com/pan-unit42/dotnetfile/blob/main/examples/

## Documentation

The full documentation can be found at https://pan-unit42.github.io/dotnetfile/

## Authors

This project was started in 2016 with the development of the parser library for internal use at Palo Alto Networks. It was improved/extended with the interface library and open-sourced in 2022 by the following people:

- Bob Jung (parser library)
- Yaron Samuel (parser library) [@yaron_samuel](https://twitter.com/yaron_samuel)
- Dominik Reichel (parser and interface libraries) [@TheEnergyStory](https://twitter.com/TheEnergyStory)

This project is a work in progress. If you find any issues or have any suggestions, please report them to the GitHub project page.