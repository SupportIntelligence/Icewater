
rule ofc8_3191a64bc6220b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=ofc8.3191a64bc6220b12"
     cluster="ofc8.3191a64bc6220b12"
     cluster_size="33"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="smspay riskware shedun"
     md5_hashes="['9d9ff374b7494e1516d02d7c9a33b63b09b95ea2','c7baa5af29762e693ac36fa81518019e558a07e2','d247c683691283c513dcec4d2f394aac1228c348']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=ofc8.3191a64bc6220b12"

   strings:
      $hex_string = { b42e039d89c6bc066368b2f67d0c3f671f7fe55fd8a539f0080152d77142e8ff5d1d98e6ad84ac005693e3cdd4dc541559328c30b16f23384533bb75d1a1777e }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
