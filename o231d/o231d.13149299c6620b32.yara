
rule o231d_13149299c6620b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o231d.13149299c6620b32"
     cluster="o231d.13149299c6620b32"
     cluster_size="8"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="smspay riskware androidos"
     md5_hashes="['b4f41ae8b5d3f71ead38f73283546f91a49be583','c4ff46778e91069814b1c9ece79ead814758511b','545bace97876696483219b97eb7bad80f9986f88']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o231d.13149299c6620b32"

   strings:
      $hex_string = { d0ff5658974c93c67343f185291eeb701ae457e535c2dcabc0bd80ba4f01db308b8d5165e96f1561be67419a1fc5f624e33953ddb3ad52d4753f493c3b59aa74 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
