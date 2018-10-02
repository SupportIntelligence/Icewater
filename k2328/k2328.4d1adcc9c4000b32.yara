
rule k2328_4d1adcc9c4000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2328.4d1adcc9c4000b32"
     cluster="k2328.4d1adcc9c4000b32"
     cluster_size="93"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe html iframeref"
     md5_hashes="['068e833d8c8328d235ac87f4a2938b4c8eda8bb6','fe99db0d4e8e546ea9e0063fe02b39c836a3ed37','e07ba36bcd8169bfa214ed2d2231397cf5aba2bb']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2328.4d1adcc9c4000b32"

   strings:
      $hex_string = { 3c3f786d6c2076657273696f6e3d22312e302220656e636f64696e673d2269736f2d383835392d32223f3e3c21444f43545950452068746d6c205055424c4943 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
