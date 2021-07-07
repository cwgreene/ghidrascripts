echo "Need at least ghidra 9.2 to have this work correctly"
echo -n "Ghidra Directory (used to get version): "
read GHIDRA_INSTALL_DIRECTORY
GHIDRA_VERSION=$(basename $GHIDRA_INSTALL_DIRECTORY)
GHIDRA_PLUGINS_DIR="${GHIDRA_INSTALL_DIRECTORY}"/Ghidra/Features/Base/lib
echo "Downloading jars into $GHIDRA_PLUGINS_DIR"
for jar in jackson-core-2.11.3.jar jackson-databind-2.11.3.jar jackson-annotations-2.11.3.jar; do
    component=$(echo -n $jar | sed 's/[^-]*-\([^-]*\)-.*/\1/')
    echo "Downloading $jar for component $component"
    curl -s "https://repo1.maven.org/maven2/com/fasterxml/jackson/core/jackson-$component/2.11.3/$jar" -o "$GHIDRA_PLUGINS_DIR/$jar"
done
