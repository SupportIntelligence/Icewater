
rule ofc8_3111a554dec30912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=ofc8.3111a554dec30912"
     cluster="ofc8.3111a554dec30912"
     cluster_size="126"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="smspay riskware shedun"
     md5_hashes="['bd0d90873690609a50020ed97000c7da1b1d13e5','a36526c8589bc29a485d22b8dcaf2fa82c108c89','3a1c8e52717b3b7ecb456e840a655edde16c1adc']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=ofc8.3111a554dec30912"

   strings:
      $hex_string = { 1fadf7314d78ce6ac6fa7acd4516d91c52f29c5ba527bc19bfb36f124975941b5d50406510a705081ea199000c2685368d0390d60972e8db86d33776bada4e02 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
