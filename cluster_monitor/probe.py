"""Remote probe script and the parser for its output.

The script is sent to each node on stdin (``bash -s``), so it never passes through a
local shell or the Windows command line. It only reads state: nvidia-smi, ps, free,
df and /proc.
"""

import re
import shlex
from typing import Dict, List, Optional, Sequence

# One round trip per node; sections are delimited by "@@<name>" lines.
# __DF_ARGS__ is replaced by the quoted mount points to report (see build_script).
_SCRIPT_TEMPLATE = r"""
echo "@@nproc $(nproc)"
echo "@@load $(cat /proc/loadavg)"
echo "@@mem $(free -m | awk 'NR==2{print $2, $3, $7}')"
echo "@@disk"
__DF_ARGS__
echo "@@gpu"
gpu=$(nvidia-smi --query-gpu=index,uuid,name,memory.used,memory.total,utilization.gpu,temperature.gpu \
  --format=csv,noheader,nounits)
echo "$gpu"
echo "@@apps"
# Idle GPUs without persistence mode can pay ~30 s per nvidia-smi call; a process
# always holds some memory, so skip the second call when every card reads 0 MiB.
apps=""
echo "$gpu" | awk -F', *' '$4>0{f=1} END{exit !f}' && \
  apps=$(nvidia-smi --query-compute-apps=gpu_uuid,pid,used_memory --format=csv,noheader,nounits)
echo "$apps"
echo "@@ps"
pids=$(echo "$apps" | awk -F', *' 'NF>=2{print $2}' | sort -u | paste -sd, -)
[ -n "$pids" ] && ps -o pid= -o user:32= -o etime= -o args= -p "$pids" | cut -c1-240
echo "@@top"
ps -e -o user:32= -o pcpu= | awk '{c[$1]+=$2} END{for(u in c) if(c[u]>=50) print u, c[u]}'
"""

_RANGE = re.compile(r"^(.*?)(\d+)-(\d+)$")


def build_script(disks: Sequence[str] = ()) -> str:
    """Return the probe script; ``disks`` are mount points whose usage is reported."""
    if disks:
        mounts = " ".join(shlex.quote(d) for d in disks)
        df = f"df -P -B1G {mounts} 2>/dev/null | awk 'NR>1{{print $6, $2, $3}}'"
    else:
        df = ":"
    return _SCRIPT_TEMPLATE.replace("__DF_ARGS__", df)


REMOTE_SCRIPT = build_script()


def parse_list(text: str) -> List[str]:
    """Split a comma/space separated list and expand ``node1-20`` style ranges."""
    items: List[str] = []
    for token in re.split(r"[,\s]+", text.strip()):
        if not token:
            continue
        match = _RANGE.match(token)
        if match and int(match.group(2)) <= int(match.group(3)):
            prefix, start, end = match.group(1), int(match.group(2)), int(match.group(3))
            items.extend(f"{prefix}{i}" for i in range(start, end + 1))
        else:
            items.append(token)
    return list(dict.fromkeys(items))


def format_list(items: Sequence[str]) -> str:
    """Inverse of parse_list: collapse consecutive ``prefixN`` names into ranges."""
    parts: List[str] = []
    run: List[int] = []
    run_prefix = ""

    def flush() -> None:
        if not run:
            return
        if len(run) >= 3:
            parts.append(f"{run_prefix}{run[0]}-{run[-1]}")
        else:
            parts.extend(f"{run_prefix}{n}" for n in run)
        run.clear()

    for item in items:
        match = re.match(r"^(.*?)(\d+)$", item)
        if match and match.group(1) == run_prefix and run and int(match.group(2)) == run[-1] + 1:
            run.append(int(match.group(2)))
            continue
        flush()
        if match and not match.group(2).startswith("0"):
            run_prefix = match.group(1)
            run.append(int(match.group(2)))
        else:
            run_prefix = ""
            parts.append(item)
    flush()
    return ", ".join(parts)


def _split_sections(text: str) -> Dict[str, List[str]]:
    """Split remote output into {section: lines}; header values become line 0."""
    sections: Dict[str, List[str]] = {}
    current: Optional[str] = None
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("@@"):
            name, _, rest = line[2:].partition(" ")
            current = name
            sections[current] = [rest] if rest else []
        elif current is not None and line:
            sections[current].append(line)
    return sections


def _csv(line: str) -> List[str]:
    return [part.strip() for part in line.split(",")]


def parse_node(text: str) -> Dict:
    """Parse the remote script output into a JSON-serialisable node record."""
    sec = _split_sections(text)
    load = sec.get("load", ["0 0 0"])[0].split()
    mem = [int(v) for v in sec.get("mem", ["0 0 0"])[0].split()]

    procs: Dict[str, Dict] = {}
    for line in sec.get("ps", []):
        parts = line.split(None, 3)
        if len(parts) >= 3:
            procs[parts[0]] = {
                "user": parts[1],
                "etime": parts[2],
                "cmd": parts[3] if len(parts) > 3 else "",
            }

    apps_by_gpu: Dict[str, List[Dict]] = {}
    for line in sec.get("apps", []):
        uuid, pid, used = _csv(line)[:3]
        info = procs.get(pid, {"user": "?", "etime": "", "cmd": ""})
        apps_by_gpu.setdefault(uuid, []).append(
            {"pid": pid, "mem_mib": int(used) if used.isdigit() else 0, **info}
        )

    gpus = []
    for line in sec.get("gpu", []):
        idx, uuid, name, used, total, util, temp = _csv(line)[:7]
        gpus.append(
            {
                "index": int(idx),
                "name": name.replace("NVIDIA ", ""),
                "mem_used": int(used),
                "mem_total": int(total),
                "util": int(util) if util.isdigit() else 0,
                "temp": int(temp) if temp.isdigit() else 0,
                "procs": apps_by_gpu.get(uuid, []),
            }
        )

    disks = []
    for line in sec.get("disk", []):
        mount, size, used = line.split()[:3]
        disks.append({"mount": mount, "size_gb": int(size), "used_gb": int(used)})

    cpu_users = []
    for line in sec.get("top", []):
        user, pcpu = line.rsplit(None, 1)
        cpu_users.append({"user": user, "pcpu": float(pcpu)})
    cpu_users.sort(key=lambda u: -u["pcpu"])

    return {
        "nproc": int(sec.get("nproc", ["0"])[0] or 0),
        "load": [float(v) for v in load[:3]],
        "mem_total_mib": mem[0],
        "mem_used_mib": mem[1],
        "mem_avail_mib": mem[2],
        "disks": disks,
        "gpus": gpus,
        "cpu_users": cpu_users,
    }
