#!/usr/bin/env python3
import socket
import struct
import requests
import os
import subprocess
import yaml
import json
import time

CONFIG_FILE = "config.yaml"

def ip_to_hex(ip):
    ip_int = struct.unpack("!I", socket.inet_aton(ip))[0]
    return f"0x{ip_int:08x}"

def get_crowdsec_bans(api_url, api_key):
    headers = {
        "X-Api-Key": api_key,
        "Content-Type": "application/json"
    }
    r = requests.get(f"{api_url}/v1/decisions?type=ban&scope=Ip", headers=headers)
    r.raise_for_status()
    (decisions) = r.json()
    if type(decisions) == list:
        banned_ips = [d["value"] for d in decisions if isinstance(d, dict)]
        return banned_ips
    else: return []

def update_bpf_map(map_path, ip_list):
    print("[DEBUG] Đang cập nhật BPF map...")
    for ip in ip_list:
        key = [f"0x{b:02x}" for b in socket.inet_aton(ip)]
        value = ["0x01"]
        try:
            subprocess.run([
                "bpftool", "map", "update", "pinned", map_path,
                "key"] + key + ["value"] + value
            , check=True)
            print(f"[+] Đã chặn IP {ip}")
        except subprocess.CalledProcessError as e:
            print(f"[!] Lỗi chặn IP {ip}: {e}")

def clear_bpf_map(map_path):
    try:
        # Lấy danh sách key hiện có trong map
        output = subprocess.check_output(["bpftool", "map", "dump", "pinned", map_path], text=True)
        lines = json.loads(output)
        for line in lines:
            key = line["key"]
            hex_bytes = []
            for b in key.to_bytes(4, 'big'):
                hex_bytes.append(f"0x{b:02x}")
            hex_bytes.reverse()
            subprocess.run(["bpftool", "map", "delete", "pinned", map_path, "key"] + hex_bytes, check=True)
    except subprocess.CalledProcessError as e:
        print("Lỗi")
def main():
    with open(CONFIG_FILE) as f:
        config = yaml.safe_load(f)

    api_url = config["crowdsec"]["lapi_url"]
    api_key = config["crowdsec"]["api_key"]
    map_name = config["map_name"]
    while True:
        banned_ips = get_crowdsec_bans(api_url, api_key)
        print(banned_ips)
        print(f"[+] Lấy {len(banned_ips)} IP từ CrowdSec")
        print("[DEBUG] Danh sách IP nhận được:", banned_ips)
        map_path = f"/sys/fs/bpf/{map_name}"
        if not os.path.exists(map_path):
            print(f"[!] Map {map_path} không tồn tại. Hãy load XDP trước.")
            return
        clear_bpf_map(map_path)
        update_bpf_map(map_path, banned_ips)
        time.sleep(60)

if __name__ == "__main__":
    main()
