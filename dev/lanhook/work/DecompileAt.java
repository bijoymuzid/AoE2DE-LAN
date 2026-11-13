// DecompileAt.java — headless targeted decompiler for the AoE2DE .text dump.
// Args: hex VAs (0x...) to disassemble, create a function at, and decompile.
import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.util.task.ConsoleTaskMonitor;

public class DecompileAt extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        DecompInterface ifc = new DecompInterface();
        ifc.openProgram(currentProgram);
        ConsoleTaskMonitor mon = new ConsoleTaskMonitor();
        FunctionManager fm = currentProgram.getFunctionManager();
        for (String a : args) {
            Address va = toAddr(Long.parseUnsignedLong(a.replace("0x", ""), 16));
            println("===== " + a + " =====");
            DisassembleCommand cmd = new DisassembleCommand(va, null, true);
            cmd.applyTo(currentProgram, mon);
            Function f = fm.getFunctionContaining(va);
            if (f == null) {
                f = createFunction(va, "f_" + a);
            }
            if (f == null) { println("no function at " + a); continue; }
            DecompileResults res = ifc.decompileFunction(f, 120, mon);
            if (res.decompileCompleted()) {
                println(res.getDecompiledFunction().getC());
            } else {
                println("decompile failed: " + res.getErrorMessage());
            }
        }
    }
}
