
rule j2319_5212754ddae30b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j2319.5212754ddae30b12"
     cluster="j2319.5212754ddae30b12"
     cluster_size="13"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="scam fakealert html"
     md5_hashes="['3a2302366114be1a8da26b1be6ebd24f6fb1771c','e4fc060db5cf4db6c96be1145da22243a6febc8f','f55056f40882640d1313d8872991741184337486']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=j2319.5212754ddae30b12"

   strings:
      $hex_string = { 737446756c6c73637265656e28456c656d656e742e414c4c4f575f4b4559424f4152445f494e50555429290a7d0a0a66756e6374696f6e2066696e286129207b }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
