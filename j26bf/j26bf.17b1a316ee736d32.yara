
rule j26bf_17b1a316ee736d32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j26bf.17b1a316ee736d32"
     cluster="j26bf.17b1a316ee736d32"
     cluster_size="4"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="grwtpstealer stealer malicious"
     md5_hashes="['ea2bf6be81bb1dd8312eb001f56cc499b52c5743','516b2618625f833cf0eea0d1a59ffc01f8c4ae83','8e1cd372b18cebddd9b845b21fdf80dbe2c0d40c']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=j26bf.17b1a316ee736d32"

   strings:
      $hex_string = { 0a16fe01130b110b2d0c00178001000004dda904000072a803007072f803007028060000066f0f00000a721e0200706f1000000a16fe01130b110b2d0c001780 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
