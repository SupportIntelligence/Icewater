
rule k2319_581a9699c2200912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.581a9699c2200912"
     cluster="k2319.581a9699c2200912"
     cluster_size="53"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['ade6d3449bfabc3ba17c5e9a2a6270cbd2648368','e2b2033409a52a343ef2efb2c0b5bb6099072573','0622ecda8e87e829fb71eecf5fd219d00950dc04']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.581a9699c2200912"

   strings:
      $hex_string = { 66696e6564297b72657475726e20415b455d3b7d76617220533d282835382c3078314545293e3d3132373f283133392e2c30786363396532643531293a28332e }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
