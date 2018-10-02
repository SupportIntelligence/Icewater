
rule m2319_2b0d9cc1c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.2b0d9cc1c8000b12"
     cluster="m2319.2b0d9cc1c8000b12"
     cluster_size="16"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="coinhive miner coinminer"
     md5_hashes="['e809b5efeeadf861d6a65daf0318e1c796d9e80b','19df5928dd302b383005e2a2914a0592452d5a7e','a30c442bde844c4388ce7b3eb3aa0002451d2695']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m2319.2b0d9cc1c8000b12"

   strings:
      $hex_string = { 297b5f30786463323166397c3d3078313c3c5f30783332343538373b7d7d292c746869733b7d2c27676574526573756c7473273a66756e6374696f6e28297b72 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
