
rule m2319_2b091ec9c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.2b091ec9c8000b12"
     cluster="m2319.2b091ec9c8000b12"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="coinhive miner script"
     md5_hashes="['3ec7c86289de1fc5c54351d11178f61ea9f81ea0','b4d7034ceeb2dd2ebe399f9678a5afcffdf0d1e7','9b788e21ced9a153f2efe176609f487ecd1a808b']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m2319.2b091ec9c8000b12"

   strings:
      $hex_string = { 297b5f30786463323166397c3d3078313c3c5f30783332343538373b7d7d292c746869733b7d2c27676574526573756c7473273a66756e6374696f6e28297b72 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
