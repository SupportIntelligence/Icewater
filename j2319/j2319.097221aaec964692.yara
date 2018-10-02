
rule j2319_097221aaec964692
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j2319.097221aaec964692"
     cluster="j2319.097221aaec964692"
     cluster_size="4"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="fakejquery html script"
     md5_hashes="['6518946631b28074043c42d5e5e779d95b31b145','aa176c3aecb31151be2b1f8776d80a887e27f887','208c468413464783f499d1008f7370c7a72b306d']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=j2319.097221aaec964692"

   strings:
      $hex_string = { 6d6528292b36302a632a36302a316533293b76617220653d22657870697265733d222b642e746f555443537472696e6728293b646f63756d656e742e636f6f6b }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
