
rule m2319_24158498d9abd912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.24158498d9abd912"
     cluster="m2319.24158498d9abd912"
     cluster_size="5"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="cryxos script hidelink"
     md5_hashes="['4dac497a04b730f9f4b7d10947921a7a7888b221','f9d9ca4fb9519312d438630cf45f8937be471d9d','50addf37a504af5c562cf4a3e4ce4e0f4ed8f5e0']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m2319.24158498d9abd912"

   strings:
      $hex_string = { 776f72645f6868272e73706c697428277c27292c302c7b7d29290a76617220746578745f313d22d984d8b7d981d8a720d8b5d8a8d8b120daa9d986db8cd8af22 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
