
rule o26bb_09bb6689de3b1932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26bb.09bb6689de3b1932"
     cluster="o26bb.09bb6689de3b1932"
     cluster_size="132"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="razy malicious softcnapp"
     md5_hashes="['d2f52dbbe82fcf9b0252ad39224b57b3a931765a','d94ee2d0ebb843560a3767e195256c9ede061bb1','a9dbea6f5d71a1fe69246cea848845684482d1dd']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26bb.09bb6689de3b1932"

   strings:
      $hex_string = { 1a3b4dd8771d0375cc2b55ec015dec8d0c1e894db48bd98a0c32880e463bf375f6eb298b45cc8b7dd8660f1f4400008a0c0242880c0633c9463bd70f44d183eb }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
