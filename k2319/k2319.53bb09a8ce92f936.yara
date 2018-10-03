
rule k2319_53bb09a8ce92f936
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.53bb09a8ce92f936"
     cluster="k2319.53bb09a8ce92f936"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="coinhive miner coinminer"
     md5_hashes="['29898bbdb00dfd1cd46298c0bb42a5a846b685f9','528f115d262aa638a02a3a33d2bf814d00eacb2e','d40f12d55a30c0bd1033e33b7ecbbacd1e294dda']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.53bb09a8ce92f936"

   strings:
      $hex_string = { 7b5f30786463323166397c3d3078313c3c5f30783332343538373b7d7d292c746869733b7d2c27676574526573756c7473273a66756e6374696f6e28297b7265 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
