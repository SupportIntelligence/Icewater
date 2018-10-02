
rule k2319_291c582adbd30b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.291c582adbd30b32"
     cluster="k2319.291c582adbd30b32"
     cluster_size="4"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="miner coinhive riskware"
     md5_hashes="['1c79952a7d5273cccb81e37bfd46c6de419e7577','68495feec14235bdc13dc0de9c784b11c073c6e7','dcd5c7949f87a1cc3f709944002777e603ebdb35']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.291c582adbd30b32"

   strings:
      $hex_string = { 6d632e79616e6465782e72752f77617463682f343835333435363022207374796c653d22706f736974696f6e3a6162736f6c7574653b206c6566743a2d393939 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
