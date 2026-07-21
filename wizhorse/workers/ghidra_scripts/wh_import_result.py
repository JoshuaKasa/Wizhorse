import json


def main():
    args = getScriptArgs()
    output_path = args[0]
    payload = {
        "program_name": currentProgram.getName(),
        "analyzed": True,
        "warnings": [],
    }
    with open(output_path, "w") as output_file:
        json.dump(payload, output_file)


main()
