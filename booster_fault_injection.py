# coding=utf-8
#! /usr/bin/python3

from bcc import BPF, USDT
import sys
import os
import signal
import time

# 定义 BPF C 代码源文件名
BPF_SOURCE_FILE = "fault_injection.src"

# defines the probe point corresponding to the fault injection function.
fn_table = {
    "DmgChangeWear": ("DmgChangeWear", "data mgr get various wear to predicte disk life."),
    "DmgChangeCheckWhitelist": ("DmgChangeCheckWhitelist", "data mgr check whitelist."),
    "DmgChangeCheckWhitelistCache": ("DmgChangeCheckWhitelistCache", "data mgr check whitelist cache."),
    "DcmReturnLinkErr": ("DcmReturnLinkErr", "data collect mgr meet link err when getting data from agent."),
    "DrmReturnErr": ("DrmReturnErr", "drm get health info failed."),
    "CliReturnTimeOut30S": ("CliReturnTimeOut30S", "cli query info failed."),
    "CliReturnTimeOut90S": ("CliReturnTimeOut90S", "cli query info failed."),
    "DrmDiskDiagReponseParseFail": ("DrmDiskDiagReponseParseFail", "drm disk diag parse response failed."),
    "DcaCreatePipeFail": ("DcaCreatePipeFail", "dca create pipe failed."),
    "DcaClosePipeFail": ("DcaClosePipeFail", "dca close pipe failed."),
    "SpdkReturnJsonTimeOut": ("SpdkReturnJsonTimeOut", "spdk return json time out."),
    "DcaGetPohFail": ("DcaGetPohFail", "dca get power on hour failed."),
    "DcaGetDhaSingleFail": ("DcaGetDhaSingleFail", "dha get single disk info failed."),
    "CliEnableCollect": ("CliEnableCollect", "cli set dha collect no interval."),
    "DhaEbpfCheckEvent": ("DhaEbpfCheckEvent", "dha ebpf reader check event."),
    "DhaEbpfGetSnErr": ("DhaEbpfGetSnErr", "dha ebpf reader get sn err."),
    "DhaEbpfCorruptShm": ("DhaEbpfCorruptShm", "dha ebpf reader corrupt shm."),
    "DhaEbpfReaderLockUp": ("DhaEbpfReaderLockUp", "dha ebpf reader lockup."),
    "DhaEbpfProducerLockUp": ("DhaEbpfProducerLockUp", "dha ebpf producer lockup."),
    "DrmDiskDiagOfflineDiskFail": ("DrmDiskDiagOfflineDiskFail", "drm disk diagnose offline disk failed"),
    "DrmDiskDiagOnlineDiskFail": ("DrmDiskDiagOnlineDiskFail", "drm disk diagnose online disk failed"),
    "DrmDiskDiagSelfTestDiskFail": ("DrmDiskDiagSelfTestDiskFail", "drm disk diagnose selftest disk prefail"),
    "DrmDiskDiagChangeLimitFail": ("DrmDiskDiagChangeLimitFail", "drm disk diagnose change limit failed"),
    "DrmDiskDiagOnlineDiagFail": ("DrmDiskDiagOnlineDiagFail", "drm disk diagnose online diag failed"),
    "DrmDiskDiagUpdateDiagStatusFail": ("DrmDiskDiagUpdateDiagStatusFail", "drm disk diagnose update diag status failed"),
    "DrmDiskDiagGetDiagInfoFail": ("DrmDiskDiagGetDiagInfoFail", "drm disk diagnose get diag info failed"),
    "DrmDiskDiagFormatInfoFail": ("DrmDiskDiagFormatInfoFail", "drm disk diagnose format info failed"),
    "DcaGetSataHddDhaInfo": ("DcaGetSataHddDhaInfo", "dca get sata hdd dha info"),
    "DmgGetDhaInfoFail": ("DmgGetDhaInfoFail", "data mgr get dha info failed"),
    "DrmSetDiskDiagMonthLifeCount": ("DrmSetDiskDiagMonthLifeCount", "drm set disk diag month and life count"),
    "DrmSmartTpSkipFeatureIdHook": ("DrmSmartTpSkipFeatureIdHook", "-u featureId :  Drm skip feature id process"),
    "DrmSlowDiskDetectSkipUpdateDiskPerfTp": ("DrmSlowDiskDetectSkipUpdateDiskPerfTp", "drm slow disk skip update disk perf"),
    "DrmSlowDiskDetectGetIostatFailTp": ("DrmSlowDiskDetectGetIostatFailTp", "drm slow disk get disk iostat fail"),
    "DrmDprDiskInPrefail": ("DrmDprDiskInPrefail", "drm dpr fail for disk in"),
    "DhasTriggerIoerr": ("DhasTriggerIoerr", "Inject IO error event for DHA. Params: diskId,opcode,protocol,senseKey,senseCode"),
    "DrmDprSetNvmeEntrysPrefail": ("DrmDprSetNvmeEntrysPrefail", "Set NVMe prefail by diskId. Params: diskId1,diskId2,... (optional)")
}


def print_help():
    print("Usage: python booster_fault_injection.py <pid> [fn1] [-p param1] [fn2] [-p param2] ...")
    print("supported fault injection functions:")
    for fn, (probe, description) in fn_table.items():
        print(f" - {fn:<35} ({description})")

def main():
    if len(sys.argv) < 2 or sys.argv[1] == "-h":
        print_help()
        sys.exit(0)

    # 从文件加载 BPF C 代码
    try:
        with open(BPF_SOURCE_FILE, 'r') as f:
            bpf_src = f.read()
    except FileNotFoundError:
        print(f"Error: BPF source file '{BPF_SOURCE_FILE}' not found.")
        sys.exit(1)

    # 重写参数解析逻辑以支持 -p
    try:
        procid = int(sys.argv[1])
    except (ValueError, IndexError):
        print("Invalid or missing PID.")
        print_help()
        sys.exit(1)

    # 解析函数及其可选参数
    enabled_fns = {} # 使用字典存储: { "函数名": "参数" or None }
    cflags = []      # 存储要传递给编译器的 cflags
    
    args = sys.argv[2:]
    i = 0
    while i < len(args):
        fn_name = args[i]
        if fn_name not in fn_table:
            print(f"Warning: function '{fn_name}' not found in fn_table. Skipping.")
            i += 1
            continue

        # 检查下一个参数是否是 -p
        if i + 2 < len(args) and args[i+1] == '-p':
            param = args[i+2]
            enabled_fns[fn_name] = param
            # 为该函数动态构建一个 C 编译器宏定义
            # 例如：-DPARAMS_DcaGetPohFail="/dev/nvme0n1"
            # 注意参数值需要用引号包围，以成为 C 语言中的字符串
            cflag = f'-DPARAMS_{fn_name}="{param}"'
            cflags.append(cflag)
            print(f"Found parameter for {fn_name}: {param}. Adding cflag: {cflag}")
            i += 3 # 跳过 fn_name, -p, 和 param
        else:
            enabled_fns[fn_name] = None
            i += 1

    if not enabled_fns:
        print("No valid functions to enable were provided.")
        print_help()
        sys.exit(1)

    # set the USDT tracepoint and enable probes
    try:
        u = USDT(pid=procid)
        for fn_name in enabled_fns.keys():
            probe_name = fn_table[fn_name][0]
            u.enable_probe(probe=probe_name, fn_name=fn_name)
            print(f"Enabled probe: {probe_name} for function: {fn_name}")
    except Exception as e:
        print(f"Error setting up USDT probes for PID {procid}.")
        print(f"Details: {e}")
        sys.exit(1)

    # 在初始化 BPF 时传入 cflags
    b = BPF(text=bpf_src, cflags=cflags, usdt_contexts=[u])
    
    # 检查是否启用了延时注入探针
    is_timeout_injection_enabled = ("CliReturnTimeOut30S" in enabled_fns or
                                    "CliReturnTimeOut90S" in enabled_fns)

    if is_timeout_injection_enabled:
        print("Timeout injection probe enabled. Monitoring process state...")
        duration = 30 if "CliReturnTimeOut30S" in enabled_fns else 90
        try:
            while True:
                with open(f"/proc/{procid}/stat") as f:
                    state = f.read().split()[2]
                if state == 'T': 
                    print(f"Probe hit! Process {procid} is now STOPPED.")
                    print(f"Sleeping here in the controller for {duration} seconds...")
                    time.sleep(duration)
                    print(f"Waking up process {procid} with SIGCONT.")
                    os.kill(procid, signal.SIGCONT)
                    print("Process resumed. Waiting for the next hit...")
                time.sleep(0.1)
        except (FileNotFoundError, KeyboardInterrupt) as e:
            print(f"\nExiting... ({type(e).__name__})")
            try:
                os.kill(procid, signal.SIGCONT)
            except ProcessLookupError:
                pass
    else:
        print("Start USDT tracing (standard mode)...")
        b.trace_print()

if __name__ == "__main__":
    main()
