
rule ofc8_3133a554d6c30912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=ofc8.3133a554d6c30912"
     cluster="ofc8.3133a554d6c30912"
     cluster_size="11"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="smspay riskware shedun"
     md5_hashes="['cbdbb3094d7bc1f3f27396fa6351aa4beba21c08','6fc359fb6deedf3d32a24559e8157202243011ef','d64dec9a7882eeefd73a21266282bb4c0cfc37f6']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=ofc8.3133a554d6c30912"

   strings:
      $hex_string = { 1fadf7314d78ce6ac6fa7acd4516d91c52f29c5ba527bc19bfb36f124975941b5d50406510a705081ea199000c2685368d0390d60972e8db86d33776bada4e02 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
