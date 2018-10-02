
rule k2319_610e3949c0000912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.610e3949c0000912"
     cluster="k2319.610e3949c0000912"
     cluster_size="223"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="multiplug script browext"
     md5_hashes="['a5df56cb3919d8273bd6f581296c9cd3c0c67740','4ec26c01326f2a2a93715f08136fe4d33026bf55','089f2d6e928c9f31ee96db154b04097ec5c7f14c']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.610e3949c0000912"

   strings:
      $hex_string = { 623c5a3b7d7d3b2866756e6374696f6e28297b766172204f373d22686f222c493d22656e74222c55373d226164222c56373d28307842353c2838312e2c313339 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
