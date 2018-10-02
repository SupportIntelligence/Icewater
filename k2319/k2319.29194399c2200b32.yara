
rule k2319_29194399c2200b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.29194399c2200b32"
     cluster="k2319.29194399c2200b32"
     cluster_size="85"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['c94c456672e3c47344fc4a0b4d5df31d719a8fdf','2ad52edcb0117aed32b784b4677871ff0773d029','03e4665d1043ca01cb3067b8ec079a902f6fb3ae']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.29194399c2200b32"

   strings:
      $hex_string = { 6566696e6564297b72657475726e20565b6c5d3b7d76617220493d282830783138392c31372e304531293e3d283134312e3945312c33372e293f283078313642 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
