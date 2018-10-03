
rule n26bb_4b949554c1f74b14
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bb.4b949554c1f74b14"
     cluster="n26bb.4b949554c1f74b14"
     cluster_size="7"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="virut malicious vitro"
     md5_hashes="['344d460c93ad071c833939be0816125f96e5aa74','ec6f2ec8c56745c28686328f86b0121cfe9fc4cc','d10e53c139ce5c94f97c46dd817d9bc2b9fdbab1']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bb.4b949554c1f74b14"

   strings:
      $hex_string = { 7ed8f10afefc8841bdeba7906471cbe3f4fa7c1b3f713c47bbcd6137425faeafaaa5e4196256c54fa0c01758028e105724c3dd6f034efe4bb1853d77768dc90c }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
