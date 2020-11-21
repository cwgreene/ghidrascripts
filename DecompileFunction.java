//TODO write a description for this script
//@author 
//@category _NEW_
//@keybinding 
//@menupath 
//@toolbar 

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.script.GhidraScript;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.OptionsService;
import ghidra.program.model.util.*;
import ghidra.program.model.reloc.*;
import ghidra.program.model.data.*;
import ghidra.program.model.block.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.scalar.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.address.*;

public class DecompileFunction extends GhidraScript {

    public void run() throws Exception {
    	String[] arguments = getScriptArgs();

    	if(arguments.length < 2) {
    		printerr("Need to specify program");
    		return;
    	}
    	
    	String targetFunc = arguments[1];
        var decomp = setUpDecompiler(currentProgram);
        FunctionIterator funcs = currentProgram.getListing().getFunctions(true);
        for (var f : funcs) {
        	if (f.getName().equalsIgnoreCase(targetFunc)) {
        		var result = decomp.decompileFunction(f, 120, null);
        		if (result == null) {
        			printerr("Failed to decompile function");
        			return;
        		}
        		println(result.getDecompiledFunction().getC());
        	}
        }
    }
    
    private DecompInterface setUpDecompiler(Program program) {
        DecompInterface decompInterface = new DecompInterface();

        // call it to get results
        if (!decompInterface.openProgram(currentProgram)) {
            printerr("Decompile Error: " + decompInterface.getLastMessage());
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
