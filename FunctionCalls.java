//TODO write a description for this script
//@author 
//@category CustomerSubmission
//@keybinding 
//@menupath 
//@toolbar 

import java.util.List;
import java.util.Map.Entry;

import java.util.Iterator;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;

import java.util.ArrayList;

import ghidra.app.decompiler.ClangFuncNameToken;
import ghidra.app.decompiler.ClangNode;
import ghidra.app.decompiler.ClangOpToken;
import ghidra.app.decompiler.ClangStatement;
import ghidra.app.decompiler.ClangVariableToken;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.OptionsService;
import ghidra.program.model.util.*;
import ghidra.sleigh.grammar.SleighCompiler.identifier_return;
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

public class FunctionCalls extends GhidraScript {

    private DecompInterface decomp;

    class VariableJson {
        public String name;
        public int size;
        public int stackOffset;

        public VariableJson(String name, int size, int stackOffset) {
            this.name = name;
            this.size = size;
            this.stackOffset = stackOffset;
        }
    }

    class FunctionJson {
        public List<VariableJson> variables;
        public List<FunctionCallJson> calls;
        public String name;
        public String address;
        public List<String> arguments;
        public List<String> exitAddresses;

        public FunctionJson() {
            variables = new ArrayList<>();
            calls = new ArrayList<>();
            arguments = new ArrayList<>();
            exitAddresses = new ArrayList<>();
        }
    }

    class ProgramJson {
        public List<FunctionJson> functions;

        public ProgramJson() {
            this.functions = new ArrayList<>();
        }
    }

    class FunctionCallJson {
        public String funcName;
        public List<String> arguments;
        public String address;

        public FunctionCallJson(String funcName, List<String> arguments, String address) {
            this.funcName = funcName;
            this.arguments = arguments;
            this.address = address;
        }
    }

    private FunctionCallJson analyzeCall(ClangStatement clangStatement) {
        String funcName = null;
        List<String> arguments = new ArrayList<>();
        String argAcc = "";
        for (int i = 0; i < clangStatement.numChildren(); i++) {
            ClangNode child = clangStatement.Child(i);
            if (child instanceof ClangOpToken) {
                ClangOpToken optoken = (ClangOpToken) child;
                // I can't imagine this is the best way but...
                if (optoken.toString().contentEquals(",")) {
                    arguments.add(argAcc);
                    argAcc = "";
                    continue;
                }
                if (optoken.toString().contentEquals("=")) {
                    argAcc = ""; // First thing we read was a return value.
                    continue;
                }
                argAcc += optoken.getText();
            } else if (child instanceof ClangVariableToken) {
                ClangVariableToken varToken = (ClangVariableToken) child;
                argAcc += varToken.getText();
            } else if (child instanceof ClangFuncNameToken) {
                funcName = ((ClangFuncNameToken) child).toString();
            }
        }
        arguments.add(argAcc);
        return new FunctionCallJson(funcName, arguments, clangStatement.getMaxAddress().toString());
    }

    private List<FunctionCallJson> findCallSites(DecompileResults res) {
        List<FunctionCallJson> result = new ArrayList<>();
        List<ClangNode> tokens = new ArrayList<>();
        res.getCCodeMarkup().flatten(tokens);
        for (ClangNode token : tokens) {
            if (token instanceof ClangFuncNameToken) {
                if (token.Parent() instanceof ClangStatement) {
                    ClangStatement statement = (ClangStatement) token.Parent();
                    if (statement.getPcodeOp().getMnemonic().equals("CALL")) {
                        result.add(analyzeCall(statement));
                    }
                }
            }
        }
        return result;
    }

    private List<String> getExitAddresses(DecompileResults res) {
        List<String> result = new ArrayList<>();
        AddressSetView body = res.getFunction().getBody();
        Iterator<Instruction> it = getCurrentProgram().getListing().getInstructions(body, true).iterator();

        while (it.hasNext()) {
            Instruction instr = it.next();
            PcodeOp[] pcode = instr.getPcode();
            for (int i = 0; i < pcode.length; i++) {
                if (pcode[i].getMnemonic().equals("RETURN")) {
                    result.add(instr.getMinAddress().toString());
                }
            }
        }
        return result;
    }

    private Variable findVariableByName(Variable[] variables, String name) {
        for (Variable v : variables) {
            if (v.getName().equals(name)) {
                return v;
            }
        }
        return null;
    }

    public void run() throws Exception {
        String[] arguments = getScriptArgs();
        decomp = setUpDecompiler(currentProgram);
        FunctionIterator funcs = currentProgram.getListing().getFunctions(true);
        ProgramJson program = new ProgramJson();

        for (Function callingFunc : funcs) {
            if (!callingFunc.isThunk()) {
                DecompileResults decompileResults = decomp.decompileFunction(callingFunc, 60, monitor);
                
                FunctionJson callingFuncJson = new FunctionJson();
                List<String> exitAddrs = getExitAddresses(decompileResults);
                callingFuncJson.exitAddresses = exitAddrs;
                for (Parameter p : callingFunc.getParameters()) {
                    callingFuncJson.arguments.add(p.getName());
                }
                callingFuncJson.address = callingFunc.getEntryPoint().toString();
                for (Variable var : callingFunc.getLocalVariables()) {
                    VariableJson varjson = new VariableJson(var.getName(), var.getLength(), var.getStackOffset());
                    callingFuncJson.variables.add(varjson);
                }
                for (FunctionCallJson call : findCallSites(decompileResults)) {
                    callingFuncJson.calls.add(call);
                }
                callingFuncJson.name = callingFunc.getName();
                program.functions.add(callingFuncJson);
            }
        }
        ObjectMapper mapper = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);
        try {
            println(mapper.writeValueAsString(program));
        } catch (Exception e) {
            throw new RuntimeException(e);
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
