
rule k2319_18161699c2200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.18161699c2200b12"
     cluster="k2319.18161699c2200b12"
     cluster_size="69"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['25426c4dc12b9957bb50797fa8d816164649d4c1','0102e359ba22bb438b38e75aa548d96a80a8994c','dfe7bcd152c5d7a8c43aa8d910a8fae62d1ef209']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.18161699c2200b12"

   strings:
      $hex_string = { 7d3b7661722047397335623d7b27553162273a66756e6374696f6e28442c412c6b297b72657475726e20447c417c6b3b7d2c27703879273a224974222c275330 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
