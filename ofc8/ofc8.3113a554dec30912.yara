
rule ofc8_3113a554dec30912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=ofc8.3113a554dec30912"
     cluster="ofc8.3113a554dec30912"
     cluster_size="122"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="smspay riskware shedun"
     md5_hashes="['44f03102f66080f1b470750fcf592d7a722e9dfb','4230311887e399e056f691c322c473c54acbd4bf','9fc813c9e5783ed6f56999ac08388ce05443d418']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=ofc8.3113a554dec30912"

   strings:
      $hex_string = { 1fadf7314d78ce6ac6fa7acd4516d91c52f29c5ba527bc19bfb36f124975941b5d50406510a705081ea199000c2685368d0390d60972e8db86d33776bada4e02 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
