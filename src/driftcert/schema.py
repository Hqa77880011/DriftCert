"""Conservative structural compatibility for the supported JSON Schema fragment.

Defaults remain annotations: structural compatibility deliberately proves no effect
refinement and therefore is the paper's weak Schema diagnostic.
"""

from . import semantics as sem

KEYS = {
    "type",
    "properties",
    "required",
    "additionalProperties",
    "enum",
    "minimum",
    "maximum",
    "items",
    "default",
}


def supported(schema):
    if set(schema) - KEYS:
        return False
    return all(
        supported(value) for value in schema.get("properties", {}).values()
    ) and ("items" not in schema or supported(schema["items"]))


def validates(value, schema):
    if not supported(schema):
        return False
    types = {
        "object": dict,
        "array": list,
        "string": str,
        "boolean": bool,
        "integer": int,
        "number": (int, float),
        "null": type(None),
    }
    kind = schema.get("type")
    if kind and (
        kind not in types
        or (
            type(value)
            not in ((types[kind],) if isinstance(types[kind], type) else types[kind])
        )
    ):
        return False
    if "enum" in schema and not any(sem.equal(value, item) for item in schema["enum"]):
        return False
    if type(value) in (int, float):
        if "minimum" in schema and value < schema["minimum"]:
            return False
        if "maximum" in schema and value > schema["maximum"]:
            return False
    if isinstance(value, dict):
        if not set(schema.get("required", [])) <= set(value):
            return False
        properties = schema.get("properties", {})
        if schema.get("additionalProperties") is False and set(value) - set(properties):
            return False
        return all(
            validates(item, properties.get(key, {})) for key, item in value.items()
        )
    if isinstance(value, list):
        return all(validates(item, schema.get("items", {})) for item in value)
    return True


def accepts_all(old, new):
    """Establish every old structurally valid value is accepted by new."""
    if not supported(old) or not supported(new):
        return False
    if new.get("type") and old.get("type") != new["type"]:
        return False
    if "enum" in new and (
        "enum" not in old or not sem.subset(old["enum"], new["enum"])
    ):
        return False
    if new.get("minimum", float("-inf")) > old.get("minimum", float("-inf")):
        return False
    if new.get("maximum", float("inf")) < old.get("maximum", float("inf")):
        return False
    if not set(new.get("required", [])) <= set(old.get("required", [])):
        return False
    oldp, newp = old.get("properties", {}), new.get("properties", {})
    if new.get("additionalProperties") is False and (
        old.get("additionalProperties") is not False or set(oldp) - set(newp)
    ):
        return False
    if any(not accepts_all(value, newp.get(key, {})) for key, value in oldp.items()):
        return False
    if "items" in new and not accepts_all(old.get("items", {}), new["items"]):
        return False
    return True


def inferred(contract, domains):
    def shape(value):
        if value is None:
            return {"type": "null"}
        if type(value) is bool:
            return {"type": "boolean"}
        if type(value) is int:
            return {"type": "integer"}
        if type(value) is float:
            return {"type": "number"}
        if isinstance(value, str):
            return {"type": "string"}
        if isinstance(value, list):
            return {"type": "array", "items": shape(value[0]) if value else {}}
        return {"type": "object"}

    properties = {}
    for name, values in domains.items():
        values = [value for value in values if not sem.equal(value, sem.MISSING)]
        exemplar = contract.get("defaults", {}).get(name, values[0] if values else None)
        properties[name] = shape(exemplar)
    return {"type": "object", "properties": properties, "additionalProperties": False}


def compatible(case, raw):
    old = case["old"].get("schema", inferred(case["old"], case["domains"]))
    new = case["new"].get("schema", inferred(case["new"], case["domains"]))
    mapped = sem.mapped(case, raw)
    return (
        mapped is not None
        and accepts_all(old, new)
        and validates(sem.normalized(mapped, case["old"]), old)
        and validates(sem.normalized(raw, case["new"]), new)
    )
