package setup;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.script.GhidraScript;
import ghidra.app.script.GhidraState;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.OptionsService;
import ghidra.program.model.listing.Program;

public class SetupUtils {
    public static DecompInterface setUpDecompiler(Program program, GhidraState state, GhidraScript script) {
        DecompInterface decompInterface = new DecompInterface();

        // call it to get results
        if (!decompInterface.openProgram(program)) {
            script.println("Decompile Error: " + decompInterface.getLastMessage());
            return null;
        }

        DecompileOptions options;
        options = new DecompileOptions();
        
        //println(state.getTool() == null ? "No tool!" : state.getTool().getName());
        PluginTool currentTool = state.getTool();
        if (currentTool != null) {
            OptionsService service = state.getTool().getService(OptionsService.class);
            if (service != null) {
                ToolOptions opt = service.getOptions("Decompiler");
                options.grabFromToolAndProgram(null, opt, program);
            }
        }
        decompInterface.setOptions(options);

        decompInterface.toggleCCode(true);
        decompInterface.toggleSyntaxTree(true);
        decompInterface.setSimplificationStyle("decompile");

        return decompInterface;
    }
}
