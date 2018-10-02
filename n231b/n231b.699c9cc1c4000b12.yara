
rule n231b_699c9cc1c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n231b.699c9cc1c4000b12"
     cluster="n231b.699c9cc1c4000b12"
     cluster_size="7"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="faceliker script autolike"
     md5_hashes="['2f3d5ebaf5fb54e5b159dcbc57a920fe71086f7f','537bf3d4764c120fd30df53ccbeb5d5ba2b573eb','d42c91b304ab76566a9dc2f2ccb2595337f4f70e']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n231b.699c9cc1c4000b12"

   strings:
      $hex_string = { 355b695d293b207d20747279207b20646f63756d656e742e65786563436f6d6d616e6428274261636b67726f756e64496d6167654361636865272c2066616c73 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
