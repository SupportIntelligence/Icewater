
rule m2319_2b0d96c9c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.2b0d96c9c8000b12"
     cluster="m2319.2b0d96c9c8000b12"
     cluster_size="5"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="coinhive miner coinminer"
     md5_hashes="['97ed4ae76ef0222c262b162a2a7220c69687d2e2','da2e692813b21af446de602f12667bbaf7cd9939','4ea3507990e82fa332a7bdcea913104466618661']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m2319.2b0d96c9c8000b12"

   strings:
      $hex_string = { 297b5f30786463323166397c3d3078313c3c5f30783332343538373b7d7d292c746869733b7d2c27676574526573756c7473273a66756e6374696f6e28297b72 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
