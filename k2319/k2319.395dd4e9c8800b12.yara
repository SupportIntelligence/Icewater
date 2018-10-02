
rule k2319_395dd4e9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.395dd4e9c8800b12"
     cluster="k2319.395dd4e9c8800b12"
     cluster_size="4"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['02b4b5f43a7a8b2a2fe6762b81007a7dfa1a72d3','4bf71e3de7c3d245a349eb3155342095d23151ab','e35b806b7bd3a4e32ab2e80a23a9796e69c317d0']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.395dd4e9c8800b12"

   strings:
      $hex_string = { 66696e6564297b72657475726e20765b415d3b7d76617220593d2828307844412c3938293e3d34333f2832332e2c30786363396532643531293a28322c312e33 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
