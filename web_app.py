import xmltodict
import io
import zipfile
import os
from flask import Flask, render_template, request, send_file, jsonify

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024  # 50MB max

# ========== Core conversion logic (refactored from xml2terraform.py) ==========

def single_list(item):
    if not (isinstance(item, list)):
        item = [item]
    return item


def name_parser(name: str):
    return name.replace(" ", "_")


def parseMultiples(value):
    if isinstance(value, list):
        return '","'.join(value)
    else:
        return value


def deepGet(t: dict, default, keys: list):
    for key in keys:
        if not isinstance(t, dict):
            return default
        result = t.get(key, default)
        if result == default:
            return default
        t = result
    return t


def smartGet(t: dict, default: str, keys: list):
    for key in keys:
        result = t.get(key, default)
        if result == default:
            return default
        else:
            t = result
    return f'["{t}"]'


def policy_block(rule, dg, rb):
    name = f"{dg}_{rb}_{rule['@name']}"
    name = name_parser(name)
    return f"""
resource "panos_panorama_security_policy" "{name}" {{
    device_group = "{dg}"
    rulebase = "{rb}"
    rule {{
        name = "{rule["@name"]}"
        source_zones = ["{rule["from"]["member"]}"]
        source_addresses = ["{rule["source"]["member"]}"]
        source_users = {smartGet(rule, "null",["source-user","member"])}
        destination_zones = ["{rule["to"]["member"]}"]
        destination_addresses = ["{rule["destination"]["member"]}"]
        applications = ["{rule["application"]["member"]}"]
        services = ["{rule["service"]["member"]}"]
        categories = {smartGet(rule, "null",["category","member"])}
        action = "{rule["action"]}"

        description = "{rule.get("description","null")}"
        negate_source = {"true" if rule.get("negate-source", False) else "false"}
        negate_destination = {"true" if rule.get("negate-destination", False) else "false"}
        log_setting = "{rule.get("log-setting", "null")}"
        disabled = {"true" if rule.get("disabled", False) else "false"}
        group = "{deepGet(rule,"null", ["profile-setting","group","member"])}"
    }}

    lifecycle {{
        create_before_destroy = true
    }}
}}
"""


def object_block(address):
    address_type = list(address.keys())[1]
    return f"""
resource "panos_panorama_address_object" "{name_parser(address["@name"])}" {{

    device_group = "{address["dg_name"]}"
    name = "{address["@name"]}"
    value = "{address[address_type]}"
    type = "{address_type}"

    lifecycle {{
        create_before_destroy = true
    }}
}}
"""


def parse_group_members(members):
    if isinstance(members, list):
        return str(members).replace("'", '"')
    else:
        return f'["{members}"]'


def group_object_block(group):
    return f"""
# Static group
resource "panos_panorama_address_group" "example" {{
    name = "{group["@name"]}"
    description = null
    static_addresses = {parse_group_members(group["static"]["member"])}

    lifecycle {{
        create_before_destroy = true
    }}
}}
"""


def convert_xml_to_tf(xml_content: str):
    """Convert Panorama XML config to Terraform files. Returns dict of filename -> content."""
    doc = xmltodict.parse(xml_content)
    output_files = {}
    errors = []
    config_type = "unknown"

    try:
        devices_entry = doc["config"]["devices"]["entry"]
        dg_container = devices_entry.get("device-group", {})
        vsys_container = devices_entry.get("vsys", {})

        if dg_container:
            config_type = "panorama"
            device_groups = single_list(dg_container["entry"])
            rulebases = ["pre-rulebase", "post-rulebase"]
        elif vsys_container:
            config_type = "firewall"
            device_groups = single_list(vsys_container["entry"])
            rulebases = ["rulebase"]
        else:
            return {"error.txt": f"Unknown config structure. Available keys: {list(devices_entry.keys())}"}, "error"
    except KeyError as e:
        return {"error.txt": f"Missing expected XML key: {e}"}, "error"

    # Append shared config if present
    try:
        shared_dg = doc["config"]["shared"]
        device_groups += single_list(shared_dg)
    except KeyError:
        pass

    rule_count = 0
    addr_count = 0
    ag_count = 0

    for dg in device_groups:
        # Security policies
        for rulebase in rulebases:
            try:
                rules = dg[rulebase]["security"]["rules"]["entry"]
            except (KeyError, TypeError):
                continue

            rules = single_list(rules)
            multiples = 
                "category", "service", "from", "to", "destination",
                "source", "source-user", "source-hip", "application",
            ]

            dg_name = dg.get("@name", "shared")

            for rule in rules:
                for key in rule.keys():
                    if key in multiples:
                        try:
                            rule[key]["member"] = parseMultiples(rule[key]["member"])
                        except KeyError:
                            pass

                filename = f"security_policies_{dg_name}.tf"
                if filename not in output_files:
                    output_files[filename] = ""
                output_files[filename] += policy_block(rule, dg_name, rulebase)
                rule_count += 1

        # Address objects
        addresses = dg.get("address", [])
        if addresses:
            addresses = single_list(addresses["entry"])
            dg_name = dg.get("@name", "shared")
            for address in addresses:
                address["dg_name"] = dg_name
                fn = "addresses.tf"
                if fn not in output_files:
                    output_files[fn] = ""
                output_files[fn] += object_block(address)
                addr_count += 1

        # Address groups
        address_groups = dg.get("address-group", None)
        if address_groups:
            address_groups = address_groups["entry"]
            if not isinstance(address_groups, list):
                address_groups = [address_groups]
            for ag in address_groups:
                fn = "address_groups.tf"
                if fn not in output_files:
                    output_files[fn] = ""
                output_files[fn] += group_object_block(ag)
                ag_count += 1

    stats = {
        "type": config_type,
        "rules": rule_count,
        "addresses": addr_count,
        "address_groups": ag_count,
    }
    return output_files, stats


# ========== Flask routes ==========
#
#  浏览器                          Flask (app.run)
#    │                                  │
#    │  TCP 连接 :8080                  │
#    │  GET / HTTP/1.1 ─────────────→  │  收到报文
#    │                                  │  查路由表: "/" → index()
#    │                                  │  执行 index()
#    │                                  │  读取 index.html
#    │  ←───────────── HTTP/1.1 200 OK │  发回 HTML 字符串
#    │         <html>...</html>         │
#    │                                  │
#    ▼ 渲染页面                          ▼ 继续等下一个请求

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/convert", methods=["POST"])
def convert():
    if "file" not in request.files:
        return jsonify({"ok": False, "error": "No file uploaded"}), 400

    file = request.files["file"]
    if file.filename == "":
        return jsonify({"ok": False, "error": "Empty filename"}), 400

    if not file.filename.lower().endswith(".xml"):
        return jsonify({"ok": False, "error": "Please upload an .xml file"}), 400

    try:
        xml_content = file.read().decode("utf-8")
    except UnicodeDecodeError:
        return jsonify({"ok": False, "error": "File encoding must be UTF-8"}), 400

    output_files, stats = convert_xml_to_tf(xml_content)

    if stats == "error":
        err_msg = output_files.get("error.txt", "Unknown error")
        return jsonify({"ok": False, "error": err_msg}), 400

    # Create in-memory zip
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for filename, content in output_files.items():
            zf.writestr(filename, content)
    buf.seek(0)

    resp = send_file(
        buf,
        mimetype="application/zip",
        as_attachment=True,
        download_name="terraform_files.zip",
    )
    resp.headers["X-Config-Type"] = stats["type"]
    resp.headers["X-Stats-Rules"] = str(stats["rules"])
    resp.headers["X-Stats-Addresses"] = str(stats["addresses"])
    resp.headers["X-Stats-Groups"] = str(stats["address_groups"])
    return resp


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port, debug=False)
