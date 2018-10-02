
rule kfc8_3919b949c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=kfc8.3919b949c8000b12"
     cluster="kfc8.3919b949c8000b12"
     cluster_size="221"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="andr apbl banker"
     md5_hashes="['88d5def026bf64e7efd12167f6625bb6442e3f77','37734b6ad6dfb60ffb4d2985767fa9d06fb5cd59','29953746d5733d82875482a3800f2a62563cbc6f']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=kfc8.3919b949c8000b12"

   strings:
      $hex_string = { 944e7b878f9339278fcb8d28a6da0191a0134a04d12185c27a4cdb3a06e7e00648f00c3ec137f801bd9e548a9dd353bdd07e7db562e327eb253b1a0c76926be6 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
