
rule n26bb_43166a48c0000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bb.43166a48c0000932"
     cluster="n26bb.43166a48c0000932"
     cluster_size="17"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="symmi malicious attribute"
     md5_hashes="['eb9a110173152cd97e9a0e79d8645fb4e83d6f8c','1b0ea82737c8fbe5b19f02b2bb8b7cfa5ef2e2b3','b126a2021b92c89bd72d0837ae57d410ec376c23']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bb.43166a48c0000932"

   strings:
      $hex_string = { c1e9038944240c3bca7707eb038d4b058bd18d43043bc2771d8b44241885c074158b7c242057535056e8dbfcffff83c410e94b01000083be88000000040f84b6 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
