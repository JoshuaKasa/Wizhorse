import json


def main():
    args = getScriptArgs()
    output_path = args[0]
    function_manager = currentProgram.getFunctionManager()
    functions = []

    for function in function_manager.getFunctions(True):
        functions.append(
            {
                "address": str(function.getEntryPoint()),
                "name": function.getName(),
                "size": int(function.getBody().getNumAddresses()),
            }
        )

    with open(output_path, "w") as output_file:
        json.dump(functions, output_file)


main()
