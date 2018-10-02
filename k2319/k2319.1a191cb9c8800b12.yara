
rule k2319_1a191cb9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.1a191cb9c8800b12"
     cluster="k2319.1a191cb9c8800b12"
     cluster_size="32"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['f00aacccbdca7d2415ecb20e5bd07f78313f7f36','1064cdc37f72acb523662f5417f9501a6912182c','71b4c38e87963b8d4288bc64b17678feb3179fb8']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.1a191cb9c8800b12"

   strings:
      $hex_string = { 30784335292929627265616b7d3b7661722074306e31483d7b275a3671273a226574222c274a3271273a227b222c274c3968273a66756e6374696f6e284d2c51 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
