import json


def main():
    args = getScriptArgs()
    output_path = args[0]
    address_text = args[1]

    address = currentProgram.getAddressFactory().getAddress(address_text)
    if address is None:
        raise ValueError("invalid address: " + address_text)

    reference_manager = currentProgram.getReferenceManager()
    xrefs = []
    for reference in reference_manager.getReferencesTo(address):
        xrefs.append(_reference_payload("to", reference))
    for reference in reference_manager.getReferencesFrom(address):
        xrefs.append(_reference_payload("from", reference))

    with open(output_path, "w") as output_file:
        json.dump(xrefs, output_file)


def _reference_payload(direction, reference):
    return {
        "direction": direction,
        "source_address": str(reference.getFromAddress()),
        "target_address": str(reference.getToAddress()),
        "reference_type": str(reference.getReferenceType()),
    }


main()
