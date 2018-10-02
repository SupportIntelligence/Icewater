
rule k2319_6906c662c8b2e132
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.6906c662c8b2e132"
     cluster="k2319.6906c662c8b2e132"
     cluster_size="6"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script bvlbb"
     md5_hashes="['85228e7b9143f80ab0c95cd139fefb0c1562fbb8','e7cfedf0421e88543a030deae97b3adadbb6b877','f8a0c05b728fa66ed6d7367832e19af29c4c1704']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.6906c662c8b2e132"

   strings:
      $hex_string = { 535b4f5d213d3d756e646566696e6564297b72657475726e20535b4f5d3b7d76617220713d2836373c3d2830783131422c3078313933293f28322c3078636339 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
