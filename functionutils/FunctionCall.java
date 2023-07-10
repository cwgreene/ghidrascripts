package functionutils;

import java.util.List;

import ghidra.app.decompiler.ClangFuncNameToken;
import ghidra.app.decompiler.ClangNode;
import ghidra.app.decompiler.ClangStatement;

public class FunctionCall {
    public ClangFuncNameToken funcName;
    public List<ClangNode> arguments;
    public ClangStatement statement;
    public FunctionCall(ClangFuncNameToken funcName, List<ClangNode> arguments, ClangStatement statement) {
        this.funcName = funcName;
        this.arguments = arguments;
        this.statement = statement;
    }
}