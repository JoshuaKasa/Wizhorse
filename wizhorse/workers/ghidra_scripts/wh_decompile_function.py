import json

from ghidra.app.decompiler import DecompInterface


def main():
    args = getScriptArgs()
    output_path = args[0]
    address_text = args[1]

    address = currentProgram.getAddressFactory().getAddress(address_text)
    function_manager = currentProgram.getFunctionManager()
    function = function_manager.getFunctionAt(address)
    if function is None:
        function = function_manager.getFunctionContaining(address)

    if function is None:
        raise ValueError("no function found at or containing address: " + address_text)

    decompiler = DecompInterface()
    decompiler.openProgram(currentProgram)
    decompile_result = decompiler.decompileFunction(function, 30, monitor)
    pseudocode = ""
    if decompile_result and decompile_result.decompileCompleted():
        decompiled_function = decompile_result.getDecompiledFunction()
        if decompiled_function is not None:
            pseudocode = decompiled_function.getC()

    payload = {
        "address": str(function.getEntryPoint()),
        "name": function.getName(),
        "pseudocode": pseudocode,
        "callers": _callers(function),
        "callees": _callees(function),
        "referenced_strings": _referenced_strings(function),
    }
    with open(output_path, "w") as output_file:
        json.dump(payload, output_file)


def _callers(function):
    reference_manager = currentProgram.getReferenceManager()
    function_manager = currentProgram.getFunctionManager()
    callers = set()
    for reference in reference_manager.getReferencesTo(function.getEntryPoint()):
        caller = function_manager.getFunctionContaining(reference.getFromAddress())
        if caller is not None:
            callers.add(str(caller.getEntryPoint()))
        else:
            callers.add(str(reference.getFromAddress()))
    return sorted(callers)


def _callees(function):
    listing = currentProgram.getListing()
    reference_manager = currentProgram.getReferenceManager()
    function_manager = currentProgram.getFunctionManager()
    callees = set()
    instructions = listing.getInstructions(function.getBody(), True)
    for instruction in instructions:
        for reference in reference_manager.getReferencesFrom(instruction.getAddress()):
            target = function_manager.getFunctionAt(reference.getToAddress())
            if target is None:
                target = function_manager.getFunctionContaining(reference.getToAddress())
            if target is not None and target.getEntryPoint() != function.getEntryPoint():
                callees.add(str(target.getEntryPoint()))
    return sorted(callees)


def _referenced_strings(function):
    listing = currentProgram.getListing()
    reference_manager = currentProgram.getReferenceManager()
    strings = set()
    instructions = listing.getInstructions(function.getBody(), True)
    for instruction in instructions:
        for reference in reference_manager.getReferencesFrom(instruction.getAddress()):
            data = listing.getDataContaining(reference.getToAddress())
            if data is None:
                continue
            try:
                value = data.getValue()
            except Exception:
                continue
            if value is None:
                continue
            text = str(value)
            if text and _looks_like_string(text):
                strings.add(text)
    return sorted(strings)[:200]


def _looks_like_string(text):
    if len(text) < 4:
        return False
    printable = sum(1 for char in text if 32 <= ord(char) <= 126)
    return printable >= max(4, int(len(text) * 0.8))


main()
