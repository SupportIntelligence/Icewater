
rule j2319_231b5ec1c4000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j2319.231b5ec1c4000b32"
     cluster="j2319.231b5ec1c4000b32"
     cluster_size="25"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="html phish phishing"
     md5_hashes="['062cc7a5353fe853d72bf74a1fc84a1e930f4c8b','2397eb95819c90a36bc7e4c0bdde779065e0506a','94d77fa2af9076c1f5c0caf36b4bca64a9de78f2']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=j2319.231b5ec1c4000b32"

   strings:
      $hex_string = { 5055424c494320222d2f2f5733432f2f4454442048544d4c20342e3031205472616e736974696f6e616c2f2f454e223e0a3c68746d6c3e0a3c686561643e0a3c }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
