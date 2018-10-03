
rule k2319_339a1c99c6200b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.339a1c99c6200b32"
     cluster="k2319.339a1c99c6200b32"
     cluster_size="5"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="html script clicker"
     md5_hashes="['1eca890114c881cbc55d459afa0b323111a6208c','dde7dc516137f7bbd37dd2c247014686d68a97c1','b021d62843e129c606fabea5793dec56080adb4a']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.339a1c99c6200b32"

   strings:
      $hex_string = { 676f72792f64726976655f66312f223e46313c2f613e3c2f6c693e0a09090909093c6c693e3c6120687265663d22687474703a2f2f7777772e62657374657870 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
