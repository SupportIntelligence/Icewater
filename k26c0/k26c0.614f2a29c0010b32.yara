
rule k26c0_614f2a29c0010b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k26c0.614f2a29c0010b32"
     cluster="k26c0.614f2a29c0010b32"
     cluster_size="4"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="malicious heuristic attribute"
     md5_hashes="['0f66d65733803daee42746d451eb9a3a86ab2ee6','5e71beefd4b25f2f0a36ef18d8e471f6961a8eb4','4250601a9403ca8a4f586c502260266531a4c51b']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k26c0.614f2a29c0010b32"

   strings:
      $hex_string = { 4f7574707574417474726962757465002505577269746546696c65004b45524e454c33322e646c6c00000e024d657373616765426f7841005553455233322e64 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
