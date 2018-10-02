
rule n26bb_611de2e9c0800b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bb.611de2e9c0800b32"
     cluster="n26bb.611de2e9c0800b32"
     cluster_size="57"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="searchsuite bandoo unwanted"
     md5_hashes="['9059ef0393a79f5ebd299f09d8fa3f061a66240a','6c7552cbaab6465287d9cdd4e5149c2d17c2a5c1','f25e6a32bd0f817582f36e35cbbc1f579ebc4d35']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bb.611de2e9c0800b32"

   strings:
      $hex_string = { ff495c9bff475c9aff445796ff3f5491ff3b518dff324885ff2e4481ff29376ffb093577f60267c0fd0369c4ff0365beff67a5d9ff72abdbff418ed0ff1e75c6 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
