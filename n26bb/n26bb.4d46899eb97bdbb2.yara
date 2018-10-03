
rule n26bb_4d46899eb97bdbb2
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bb.4d46899eb97bdbb2"
     cluster="n26bb.4d46899eb97bdbb2"
     cluster_size="5"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="virut malicious vitro"
     md5_hashes="['c0bb3c1f9ba060a7e3a367feecb59cc1d1959e1a','32a13322f525f71a04a2475031f00346be236cff','e6c592de943f659f92c38c6de3f7fe0165d16399']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bb.4d46899eb97bdbb2"

   strings:
      $hex_string = { 7ed8f10afefc8841bdeba7906471cbe3f4fa7c1b3f713c47bbcd6137425faeafaaa5e4196256c54fa0c01758028e105724c3dd6f034efe4bb1853d77768dc90c }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
