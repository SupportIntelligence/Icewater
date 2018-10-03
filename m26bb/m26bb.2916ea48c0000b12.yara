
rule m26bb_2916ea48c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m26bb.2916ea48c0000b12"
     cluster="m26bb.2916ea48c0000b12"
     cluster_size="178"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="generickd malicious betload"
     md5_hashes="['5810ce6fd6c2a719d8d5eaed3ea7e56b43a85cc3','8b16a1edb4f8581ada6902682906df2b990c5b02','e6abce66c672590a80650a35e13dfd5a6bebd9b1']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m26bb.2916ea48c0000b12"

   strings:
      $hex_string = { c1eb1f03da8ad302d202d2468d041a02c02ac880c130884c341085db75d485f67e0c8a4c3410880f4e4785f67ff45e2bef83c52055e8989b0000c607005f5d5b }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
