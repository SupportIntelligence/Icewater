
rule k2319_53a129b976d042ba
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.53a129b976d042ba"
     cluster="k2319.53a129b976d042ba"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="coinhive miner coinminer"
     md5_hashes="['065aeb838c9a5c234270f6e5ab61cadf031e5643','a2ba3fcc3bdca7aeeec2aa8b6c39869321946fe1','f595de056130d65303bb7af298e3e3e922803353']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.53a129b976d042ba"

   strings:
      $hex_string = { 297b5f30786463323166397c3d3078313c3c5f30783332343538373b7d7d292c746869733b7d2c27676574526573756c7473273a66756e6374696f6e28297b72 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
