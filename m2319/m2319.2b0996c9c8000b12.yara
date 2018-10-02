
rule m2319_2b0996c9c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.2b0996c9c8000b12"
     cluster="m2319.2b0996c9c8000b12"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="coinhive miner script"
     md5_hashes="['c8cea4b018faefd12bce6dd8e384ec3fb20fad73','cb693563d997a8977e7c0bf8bb110f558c4efd20','8604d6d1a15051d32ba2a0a22e08d4f36c189f87']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m2319.2b0996c9c8000b12"

   strings:
      $hex_string = { 297b5f30786463323166397c3d3078313c3c5f30783332343538373b7d7d292c746869733b7d2c27676574526573756c7473273a66756e6374696f6e28297b72 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
