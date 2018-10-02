
rule o2319_53b46a48c0000912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o2319.53b46a48c0000912"
     cluster="o2319.53b46a48c0000912"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="faceliker likejack classic"
     md5_hashes="['9fe025fa3a293bad342063bc3817ffec2c5756e5','5f026ce2685ba48b2d6d4c40818f2c6d4f045a0b','ce97414bf76639ba1be8a2c38176d0a629baedc4']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o2319.53b46a48c0000912"

   strings:
      $hex_string = { 3d224142434445464748494a4b4c4d4e4f505152535455565758595a6162636465666768696a6b6c6d6e6f707172737475767778797a30313233343536373839 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
