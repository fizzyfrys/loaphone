// Loaphone headless REA scan. Run by analyzeHeadless as a post script; writes
// the raw facts (ioctl call sites, defined strings, constants, mapped blocks)
// as JSON to the path given as the first script argument.
//@category Loaphone
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.StringDataInstance;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.Varnode;
import java.io.FileWriter;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

public class LoaphoneScan extends GhidraScript {
    private static final int MAX_FUNCTIONS = 4000;

    private static String quote(String s) {
        StringBuilder b = new StringBuilder("\"");
        for (char c : s.toCharArray()) {
            if (c == '"' || c == '\\') b.append('\\').append(c);
            else if (c < 0x20) b.append(String.format("\\u%04x", (int) c));
            else b.append(c);
        }
        return b.append('"').toString();
    }

    private static boolean isIoctl(Function f) {
        Function target = f.isThunk() ? f.getThunkedFunction(true) : f;
        return target != null && target.getName().equals("ioctl");
    }

    private static void sep(StringBuilder b) {
        if (b.length() > 1) b.append(',');
    }

    @Override
    public void run() throws Exception {
        String out = getScriptArgs()[0];
        StringBuilder ioctls = new StringBuilder("[");
        StringBuilder strings = new StringBuilder("[");
        StringBuilder constants = new StringBuilder("[");
        StringBuilder sections = new StringBuilder("[");

        for (MemoryBlock m : currentProgram.getMemory().getBlocks()) {
            if (!m.isInitialized() || !m.isLoaded()) continue;
            sep(sections);
            sections.append("{\"start\":").append(m.getStart().getOffset())
                .append(",\"end\":").append(m.getEnd().getOffset() + 1).append('}');
        }

        DataIterator data = currentProgram.getListing().getDefinedData(true);
        while (data.hasNext() && !monitor.isCancelled()) {
            Data d = data.next();
            if (!StringDataInstance.isString(d)) continue;
            Object v = d.getValue();
            if (v == null) continue;
            sep(strings);
            strings.append("{\"address\":").append(d.getAddress().getOffset())
                .append(",\"value\":").append(quote(v.toString())).append('}');
        }

        DecompInterface di = new DecompInterface();
        di.openProgram(currentProgram);
        Set<String> seen = new HashSet<>();
        int count = 0;
        boolean truncated = false;
        FunctionIterator fns = currentProgram.getFunctionManager().getFunctions(true);
        while (fns.hasNext()) {
            Function f = fns.next();
            if (f.isThunk() || f.isExternal()) continue;
            if (monitor.isCancelled() || count >= MAX_FUNCTIONS) {
                truncated = true;
                break;
            }
            count++;
            DecompileResults r = di.decompileFunction(f, 30, monitor);
            HighFunction h = r.getHighFunction();
            if (h == null) {
                truncated = true;
                continue;
            }
            Iterator<PcodeOpAST> ops = h.getPcodeOps();
            while (ops.hasNext()) {
                PcodeOpAST op = ops.next();
                long at = op.getSeqnum().getTarget().getOffset();
                if (op.getOpcode() == PcodeOp.CALL) {
                    Function callee = getFunctionAt(op.getInput(0).getAddress());
                    if (callee != null && isIoctl(callee)) {
                        Varnode req = op.getNumInputs() > 2 ? op.getInput(2) : null;
                        sep(ioctls);
                        ioctls.append("{\"address\":").append(at)
                            .append(",\"function\":").append(quote(f.getName()))
                            .append(",\"request\":")
                            .append(req != null && req.isConstant() ? Long.toString(req.getOffset() & 0xffffffffL) : "null")
                            .append('}');
                    }
                }
                for (int i = 0; i < op.getNumInputs(); i++) {
                    Varnode v = op.getInput(i);
                    if (v == null || !v.isConstant()) continue;
                    long value = v.getOffset();
                    if (value < 0x01000000L || value > 0xffffffffL) continue;
                    if (!seen.add(f.getName() + ":" + value)) continue;
                    sep(constants);
                    constants.append("{\"address\":").append(at)
                        .append(",\"function\":").append(quote(f.getName()))
                        .append(",\"value\":").append(value).append('}');
                }
            }
        }
        di.dispose();

        try (FileWriter w = new FileWriter(out)) {
            w.write("{\"ioctls\":" + ioctls + "],\"strings\":" + strings + "],\"constants\":"
                + constants + "],\"sections\":" + sections + "],\"truncated\":" + truncated + "}");
        }
    }
}
