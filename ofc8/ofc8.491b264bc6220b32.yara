
rule ofc8_491b264bc6220b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=ofc8.491b264bc6220b32"
     cluster="ofc8.491b264bc6220b32"
     cluster_size="5"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="smspay riskware shedun"
     md5_hashes="['122dfd8fa0e72addbc6516fa22799db483350694','7351e78bb80ab201e5e9c2dcca23c7242e255307','b122492cc87bf5507d9af16f03390acf43198718']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=ofc8.491b264bc6220b32"

   strings:
      $hex_string = { b42e039d89c6bc066368b2f67d0c3f671f7fe55fd8a539f0080152d77142e8ff5d1d98e6ad84ac005693e3cdd4dc541559328c30b16f23384533bb75d1a1777e }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
