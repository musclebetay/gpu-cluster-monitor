"""Parser tests for the remote probe output."""

from cluster_monitor.probe import parse_node

SAMPLE = """@@nproc 48
@@load 8.89 8.60 8.36 2/549 22903
@@mem 257663 17000 231000
@@disk
/home 1863 1055
/scratch 11920 10067
@@gpu
0, GPU-a, NVIDIA GeForce RTX 4090, 22328, 24564, 97, 66
1, GPU-b, NVIDIA GeForce RTX 4090, 0, 24564, 0, 40
@@apps
GPU-a, 35001, 22322
@@ps
35001 someone 6-01:26:37 VLLM::EngineCore --model x
@@top
someone 760.5
other 120
"""

IDLE = """@@nproc 24
@@load 0.12 0.07 0.06 1/300 1
@@mem 257663 119627 135464
@@disk
@@gpu
0, GPU-x, NVIDIA TITAN Xp, 0, 12288, 0, 36
@@apps

@@ps
@@top
"""


def test_busy_node_links_processes_to_gpus() -> None:
    record = parse_node(SAMPLE)
    assert record["nproc"] == 48
    assert record["load"] == [8.89, 8.60, 8.36]
    assert record["mem_total_mib"] == 257663
    busy, idle = record["gpus"]
    assert busy["name"] == "GeForce RTX 4090"
    assert busy["procs"] == [
        {"pid": "35001", "mem_mib": 22322, "user": "someone", "etime": "6-01:26:37",
         "cmd": "VLLM::EngineCore --model x"}
    ]
    assert idle["procs"] == []
    assert [u["user"] for u in record["cpu_users"]] == ["someone", "other"]
    assert record["disks"][1] == {"mount": "/scratch", "size_gb": 11920, "used_gb": 10067}


def test_idle_node_without_process_query() -> None:
    record = parse_node(IDLE)
    assert record["gpus"][0]["procs"] == []
    assert record["disks"] == []
    assert record["cpu_users"] == []


def test_node_ranges_round_trip() -> None:
    from cluster_monitor.probe import format_list, parse_list

    nodes = parse_list("node1-4, gpu-a  node9,node9, host007")
    assert nodes == ["node1", "node2", "node3", "node4", "gpu-a", "node9", "host007"]
    assert format_list(nodes) == "node1-4, gpu-a, node9, host007"
    assert parse_list(format_list(nodes)) == nodes


def test_disk_mounts_are_quoted() -> None:
    from cluster_monitor.probe import build_script

    script = build_script(["/data", "/a b; rm -rf ~"])
    assert "df -P -B1G /data '/a b; rm -rf ~' 2>/dev/null" in script
    assert "df -P" not in build_script()
