
rule o3f0_31bb2894ea008932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3f0.31bb2894ea008932"
     cluster="o3f0.31bb2894ea008932"
     cluster_size="152"
     filetype = "PE32 executable (GUI) Intel 80386 (stripped to external PDB)"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="malicious susp conficker"
     md5_hashes="['0164f4a66405649837d58ca5577a6d18','03fcb4ff13fae6874ebbe462879ff156','1ea65406288ebb8e90312abc1f140068']"

   strings:
      $hex_string = { f439f839fc39003a0000083a0c3a103a143a183a0000203a243a200a200a00000000300a3c3a403a443a00004c3a0000543a583a5c3a600a643a683a600a700a }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
