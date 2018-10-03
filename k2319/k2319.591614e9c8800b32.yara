
rule k2319_591614e9c8800b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.591614e9c8800b32"
     cluster="k2319.591614e9c8800b32"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['7866695b302f799baa30f89e6de19d1574f34d43','8422acaf759b3d93bf98792610d24d83aa2f107a','5f26c1982f64c0a179683c79681556c73d50798b']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.591614e9c8800b32"

   strings:
      $hex_string = { 31364533293f30783144343a2830783234432c39342e374531292929627265616b7d3b766172204836583d7b27733933273a226f6e222c27543733273a22797a }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
