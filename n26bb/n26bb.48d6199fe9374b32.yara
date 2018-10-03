
rule n26bb_48d6199fe9374b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bb.48d6199fe9374b32"
     cluster="n26bb.48d6199fe9374b32"
     cluster_size="5"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="virut malicious vitro"
     md5_hashes="['9cbbda7a4453365fae4342885f6d8e2874409100','18daf91d39bffa7d19bd677e2356cdc5d041fe3f','686a469f4bf077960e123a5c2d747369b5e4631c']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bb.48d6199fe9374b32"

   strings:
      $hex_string = { 7ed8f10afefc8841bdeba7906471cbe3f4fa7c1b3f713c47bbcd6137425faeafaaa5e4196256c54fa0c01758028e105724c3dd6f034efe4bb1853d77768dc90c }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
