
rule k3e9_6a92979c1ea31912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.6a92979c1ea31912"
     cluster="k3e9.6a92979c1ea31912"
     cluster_size="7"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="nsis adload keygen"
     md5_hashes="['0f1bae9725f934f765f1bb4d3a70b0c5','365305417ad90c3b32f5330e9143c093','cfed51e40a1764f0db9f1f3463e91cb9']"

   strings:
      $hex_string = { c07c2b568d7041c1e6055703f18d78018b0685c07410837efcff750a50ff150430001083260083ee204f75e45f5ec3518b4424085355568b981408000057895c }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
