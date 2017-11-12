
rule o3e9_2b102a08d9e28912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.2b102a08d9e28912"
     cluster="o3e9.2b102a08d9e28912"
     cluster_size="2812"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="strictor noobyprotect advml"
     md5_hashes="['00375d76cadf50f91444c2107012ea5b','0059bff0b52ffac7bb94ad103ad97bf4','017714606f28cee8db3936d7b59d3399']"

   strings:
      $hex_string = { 87d5db4d487a29e6dbb027920d6ed1ab323511f3c02d198a81766eb6fc44970210dfc49b3b7a6400206f98866239c91c016085d07cdcb3b1d5e4985966e4ce5e }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
