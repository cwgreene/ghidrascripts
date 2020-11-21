# GhidraScripts

Scripts used to help with Ghidra Analysis.

# Installing

If you're using [dorat](https://github.com/cwgreene/dorat/), run
`install.sh` to install the jars (for json) into the plugin location
for your ghidra instalation. Then run `dorat --config` to point
to your checkout directory. Future versions of `install.sh` will
do that for you.

If you want to use the scripts from within ghidra, from the Script 
Manager, click the "Script Directories" button to add the checkout
directory to list of script directories.

# Building

Create a new Ghidra Scripts project. Add this directory as a linked
directory. Add jackson jar files to `~/.ghidra/GHIDRA_VERSION/plugins`.

## Scripts
- FindLibcCalls - Misnamed. Displays functions and what they call in a binary.
- FunctionCalls - Dumps function call information to json.
