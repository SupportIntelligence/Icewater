
rule k2319_591614e9c8000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.591614e9c8000b32"
     cluster="k2319.591614e9c8000b32"
     cluster_size="9"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['3957d6e83cc6c673a40ba243980ae66a24dfb5e9','86055654c840e722499b6b552e17aa09faff9ecf','800904aa6ffcdb30a71319b3fbf5e0af25c297f9']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.591614e9c8000b32"

   strings:
      $hex_string = { 31364533293f30783144343a2830783234432c39342e374531292929627265616b7d3b766172204836583d7b27733933273a226f6e222c27543733273a22797a }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
