package functionutils;

import java.util.ArrayList;
import java.util.List;

import ghidra.app.decompiler.ClangFuncNameToken;
import ghidra.app.decompiler.ClangNode;
import ghidra.app.decompiler.ClangOpToken;
import ghidra.app.decompiler.ClangStatement;
import ghidra.app.decompiler.ClangVariableToken;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.HighVariable;
import ghidra.util.task.TaskMonitor;

public class FunctionUtils {
    public static FunctionCall analyzeCall(ClangStatement clangStatement) {
        ClangFuncNameToken funcName = null;
        List<ClangNode> arguments = new ArrayList<>();
        for (int i = 0; i < clangStatement.numChildren(); i++ ) {
            ClangNode child = clangStatement.Child(i);
            if (child instanceof ClangOpToken) {
                ClangOpToken optoken = (ClangOpToken) child;
                // I can't imagine this is the best way but...
                if (optoken.toString().contentEquals(",")) {
                    continue;
                }
                arguments.add(optoken);
            } else if (child instanceof ClangVariableToken) {
            	ClangVariableToken varToken = (ClangVariableToken) child;
            	HighVariable var = varToken.getHighVariable();
                arguments.add(child);
            } else if (child instanceof ClangFuncNameToken) {
                funcName = (ClangFuncNameToken) child;
            }
        }
        return new FunctionCall(funcName, arguments, clangStatement);
    }
    
    public static List<FunctionCall> findCallSites(Function func, DecompInterface decomp, TaskMonitor monitor) {
        List<FunctionCall> result = new ArrayList<>();
        DecompileResults res = decomp.decompileFunction(func, 60, monitor);
        List<ClangNode> tokens = new ArrayList<>();
        res.getCCodeMarkup().flatten(tokens);
        for(ClangNode token : tokens) {
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
}
