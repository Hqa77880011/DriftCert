"""Independent finite input interpretation and ordered effect-prefix oracle."""

import copy


def safe(case, raw):
    mapped = {case["mapping"].get(k, k): copy.deepcopy(v) for k, v in raw.items()}
    old_values = {**copy.deepcopy(case["old"].get("defaults", {})), **mapped}
    if any(
        key not in old_values
        or type(old_values[key]) is not type(value)
        or old_values[key] != value
        for key, value in case["old"].get("requires", {}).items()
    ):
        return False
    current = {**copy.deepcopy(case["new"].get("defaults", {})), **copy.deepcopy(raw)}
    trace = []
    for effect in case["new"]["effects"]:
        if not all(
            key in current
            and type(current[key]) is type(value)
            and current[key] == value
            for key, value in effect.get("when", {}).items()
        ):
            continue
        trace.append(
            {
                key: copy.deepcopy(current[value[1:]])
                if isinstance(value, str) and value.startswith("$")
                else copy.deepcopy(value)
                for key, value in effect.items()
                if key != "when"
            }
        )
    allowed = case["old"]["allowed"]

    def prefix(index, position):
        if index == len(trace):
            return True
        if position == len(allowed):
            return False
        effect, rule = trace[index], allowed[position]
        matching = (
            effect["action"] == rule["action"]
            and all(item in rule["objects"] for item in effect["objects"])
            and effect["recipient"] in rule["recipients"]
            and effect["label"] in rule["labels"]
        )
        return (
            matching
            and prefix(index + 1, position + 1)
            or rule.get("optional", False)
            and prefix(index, position + 1)
        )

    return bool(prefix(0, 0))
