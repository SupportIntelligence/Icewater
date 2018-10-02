
rule k2319_18159699c2200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.18159699c2200b12"
     cluster="k2319.18159699c2200b12"
     cluster_size="17"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['d1b394b414a8674f5cb42df6f0ad8c59d9cd15c6','c9a68125a7ece2790440a4787c9cfa2339b32206','9129493a04fc79229d85fa2db1c8936a2f0d5b61']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.18159699c2200b12"

   strings:
      $hex_string = { 3631293f2277223a2830783133452c3635292929627265616b7d3b666f72287661722051387020696e2053396c3870297b6966285138702e6c656e6774683d3d }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
