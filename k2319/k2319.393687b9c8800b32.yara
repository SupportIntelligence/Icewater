
rule k2319_393687b9c8800b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.393687b9c8800b32"
     cluster="k2319.393687b9c8800b32"
     cluster_size="66"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['06d83d583b9753cdc249b245d657fbc6f6bd5fde','d7ab4ab0bf256df5bf9808a429869dc211f2dde2','80606fbe52b5a083f12c96590434b55eedebafe1']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.393687b9c8800b32"

   strings:
      $hex_string = { 6566696e6564297b72657475726e207a5b4c5d3b7d766172204d3d2828307834362c3131312e394531293c30783142433f2772273a2831322e383445322c3733 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
