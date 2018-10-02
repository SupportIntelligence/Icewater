
rule m231b_4996e448c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m231b.4996e448c0000b12"
     cluster="m231b.4996e448c0000b12"
     cluster_size="7"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="faceliker script autolike"
     md5_hashes="['27bc182eafd71ebaec41363b82a16738652c3805','9e64e60290c7767e4e36cd682f63cf17c24d514a','2fc32e9b418e81e58a348da7ec1f9547c938996e']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m231b.4996e448c0000b12"

   strings:
      $hex_string = { 31466b556775515173443949546d443745435a494a5345344f5a6f3973746f566a432f7a63376b792b7a483968587756774470544157574c7267533351416538 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
