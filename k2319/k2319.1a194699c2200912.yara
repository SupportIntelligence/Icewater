
rule k2319_1a194699c2200912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.1a194699c2200912"
     cluster="k2319.1a194699c2200912"
     cluster_size="76"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['fce04bbe3cff6ef906dddecd2d71403987e07b00','346532bb1f3bd2c5fc82e8f0a1540fa790d6c451','5e4487c8f86d64c4e85094a1b022157b734e3fc3']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.1a194699c2200912"

   strings:
      $hex_string = { 39293a28307837352c3078314246292929627265616b7d3b7661722044334337723d7b27773737273a226273222c27433372273a66756e6374696f6e28702c64 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
