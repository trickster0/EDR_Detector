extern crate walkdir;
extern crate colored;
//Dependencies in Cargo.toml  walkdir = "2.2.9" colored = "1.8.0"
use walkdir::WalkDir;
use std::collections::HashMap;
use colored::Colorize;

fn main() {

    println!("######################################################
#  EDR Detector by trickster0 from Telspace Systems. #
######################################################\r\n");
    let mut edrs = HashMap::new();
    edrs.insert("atrsdfw.sys","Altiris Symantec has been detected.");
    edrs.insert("avgtpx86.sys","AVG Technologies has been detected.");
    edrs.insert("avgtpx64.sys","AVG Technologies has been detected.");
    edrs.insert("naswSP.sys","Avast has been detected.");
    edrs.insert("edrsensor.sys","BitDefender SRL has been detected.");
    edrs.insert("CarbonBlackK.sys","Carbon Black has been detected.");
    edrs.insert("parity.sys","Carbon Black has been detected.");
    edrs.insert("csacentr.sys","Cisco has been detected.");
    edrs.insert("csaenh.sys","Cisco has been detected.");
    edrs.insert("csareg.sys","Cisco has been detected.");
    edrs.insert("csascr.sys","Cisco has been detected.");
    edrs.insert("csaav.sys","Cisco has been detected.");
    edrs.insert("csaam.sys","Cisco has been detected.");
    edrs.insert("rvsavd.sys","CJSC Returnil Software has been detected.");
    edrs.insert("cfrmd.sys","Comodo Security has been detected.");
    edrs.insert("cmdccav.sys","Comodo Security has been detected.");
    edrs.insert("cmdguard.sys","Comodo Security has been detected.");
    edrs.insert("CmdMnEfs.sys","Comodo Security has been detected.");
    edrs.insert("MyDLPMF.sys","Comodo Security has been detected.");
    edrs.insert("im.sys","CrowdStrike has been detected.");
    edrs.insert("csagent.sys","CrowdStrike has been detected.");
    edrs.insert("CybKernelTracker.sys","CyberArk Software has been detected.");
    edrs.insert("CRExecPrev.sys","Cybereason has been detected.");
    edrs.insert("CyOptics.sys","Cylance Inc. has been detected.");
    edrs.insert("CyProtectDrv32.sys","Cylance Inc. has been detected.");
    edrs.insert("CyProtectDrv64.sys","Cylance Inc. has been detected.");
    edrs.insert("groundling32.sys","Dell Secureworks has been detected.");
    edrs.insert("groundling64.sys","Dell Secureworks has been detected.");
    edrs.insert("esensor.sys","Endgame has been detected.");
    edrs.insert("edevmon.sys","ESET has been detected.");
    edrs.insert("ehdrv.sys","ESET has been detected.");
    edrs.insert("FeKern.sys","FireEye has been detected.");
    edrs.insert("WFP_MRT.sys","FireEye has been detected.");
    edrs.insert("xfsgk.sys","F-Secure has been detected.");
    edrs.insert("fsatp.sys","F-Secure has been detected.");
    edrs.insert("fshs.sys","F-Secure has been detected.");
    edrs.insert("HexisFSMonitor.sys","Hexis Cyber Solutions has been detected.");
    edrs.insert("klifks.sys","Kaspersky has been detected.");
    edrs.insert("klifaa.sys","Kaspersky has been detected.");
    edrs.insert("Klifsm.sys","Kaspersky has been detected.");
    edrs.insert("mbamwatchdog.sys","Malwarebytes has been detected.");
    edrs.insert("mfeaskm.sys","McAfee has been detected.");
    edrs.insert("mfencfilter.sys","McAfee has been detected.");
    edrs.insert("PSINPROC.SYS","Panda Security has been detected.");
    edrs.insert("PSINFILE.SYS","Panda Security has been detected.");
    edrs.insert("amfsm.sys","Panda Security has been detected.");
    edrs.insert("amm8660.sys","Panda Security has been detected.");
    edrs.insert("amm6460.sys","Panda Security has been detected.");
    edrs.insert("eaw.sys","Raytheon Cyber Solutions has been detected.");
    edrs.insert("SAFE-Agent.sys","SAFE-Cyberdefense has been detected.");
    edrs.insert("SentinelMonitor.sys","SentinelOne has been detected.");
    edrs.insert("SAVOnAccess.sys","Sophos has been detected.");
    edrs.insert("savonaccess.sys","Sophos has been detected.");
    edrs.insert("sld.sys","Sophos has been detected.");
    edrs.insert("pgpwdefs.sys","Symantec has been detected.");
    edrs.insert("GEProtection.sys","Symantec has been detected.");
    edrs.insert("diflt.sys","Symantec has been detected.");
    edrs.insert("sysMon.sys","Symantec has been detected.");
    edrs.insert("ssrfsf.sys","Symantec has been detected.");
    edrs.insert("emxdrv2.sys","Symantec has been detected.");
    edrs.insert("reghook.sys","Symantec has been detected.");
    edrs.insert("spbbcdrv.sys","Symantec has been detected.");
    edrs.insert("bhdrvx86.sys","Symantec has been detected.");
    edrs.insert("bhdrvx64.sys","Symantec has been detected.");
    edrs.insert("SISIPSFileFilter.sys","Symantec has been detected.");
    edrs.insert("symevent.sys","Symantec has been detected.");
    edrs.insert("vxfsrep.sys","Symantec has been detected.");
    edrs.insert("VirtFile.sys","Symantec has been detected.");
    edrs.insert("SymAFR.sys","Symantec has been detected.");
    edrs.insert("symefasi.sys","Symantec has been detected.");
    edrs.insert("symefa.sys","Symantec has been detected.");
    edrs.insert("symefa64.sys","Symantec has been detected.");
    edrs.insert("SymHsm.sys","Symantec has been detected.");
    edrs.insert("evmf.sys","Symantec has been detected.");
    edrs.insert("GEFCMP.sys","Symantec has been detected.");
    edrs.insert("VFSEnc.sys","Symantec has been detected.");
    edrs.insert("pgpfs.sys","Symantec has been detected.");
    edrs.insert("fencry.sys","Symantec has been detected.");
    edrs.insert("symrg.sys","Symantec has been detected.");
    edrs.insert("ndgdmk.sys","Verdasys Inc has been detected.");
    edrs.insert("ssfmonm.sys","Webroot Software has been detected.");
    edrs.insert("dlpwpdfltr.sys","Trend Micro Software has been detected.");

    for entry in WalkDir::new("C:\\Windows\\System32\\drivers\\") 
        .follow_links(true)
        .into_iter()
        .filter_map(|e| e.ok()) {
        let f_name = entry.file_name().to_string_lossy();
        if  edrs.contains_key(f_name.as_ref()) {
            println!("[+] {}\r\n", edrs.get(f_name.as_ref()).unwrap().green());
        } else if f_name.starts_with("EcatService") {
            println!("{}", "[+] RSA NetWitness Endpoint has been detected.\r\n".green());
        }
    }
}
