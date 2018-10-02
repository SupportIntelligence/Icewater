
rule k2319_381f14a9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.381f14a9c8800b12"
     cluster="k2319.381f14a9c8800b12"
     cluster_size="9"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['e7840718513635d87a7756ed0f9fcacbbedb0f7f','81a4deaae6170c0c6c59d561f25791c73d0b9e28','4c09edd681c8362908a1564b1634f85766dc219c']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.381f14a9c8800b12"

   strings:
      $hex_string = { 213d3d756e646566696e6564297b72657475726e20415b7a5d3b7d76617220533d2828307846392c33372e293e283132322e2c342e293f2834322e2c30786363 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
