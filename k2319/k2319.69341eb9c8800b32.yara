
rule k2319_69341eb9c8800b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.69341eb9c8800b32"
     cluster="k2319.69341eb9c8800b32"
     cluster_size="5"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['c94bc5486fa1c30c453b35cc065faddebaf844de','0cc306b02b1f97efc7435c8402e8852395bc66b0','a942e1b5ab42b840a53eaaf49a36660548d8d3b6']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.69341eb9c8800b32"

   strings:
      $hex_string = { 362e3f2830783139342c31302e33394532293a283078452c3078313231292929627265616b7d3b7661722058374638313d7b27453331273a2866756e6374696f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
