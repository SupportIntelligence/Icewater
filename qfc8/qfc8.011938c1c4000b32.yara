
rule qfc8_011938c1c4000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=qfc8.011938c1c4000b32"
     cluster="qfc8.011938c1c4000b32"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="androidos highconfidence jiagu"
     md5_hashes="['a85c0912f1d2fdf550a561cb5c215e9ccc310a85','bb6835a98b7f6b486b820a603a4ccd2886aa52f4','39ef6f166649ebb0b4f415f3a10d986c3c0eb9d8']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=qfc8.011938c1c4000b32"

   strings:
      $hex_string = { 1b4e2fd17e1acbf0d56cd71787b8275b6fd667edca867db5dec73fa057fe012592a111bb0e828f0bb663dfb7eff4c0533e9bc4e3ab4fa73bd8045e76cc51774c }

   condition:
      
      filesize > 16777216 and filesize < 67108864
      and $hex_string
}
