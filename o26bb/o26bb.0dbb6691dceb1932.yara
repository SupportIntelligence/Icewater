
rule o26bb_0dbb6691dceb1932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26bb.0dbb6691dceb1932"
     cluster="o26bb.0dbb6691dceb1932"
     cluster_size="267"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="razy genx malicious"
     md5_hashes="['aac8933e3adaabfea121a94758e2cc94ade04d40','4307952951ec1c4c7b705f1ccc3ae2ed78480ae3','35147ad3bf015c20fa741c96aa71fe02d1817d43']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26bb.0dbb6691dceb1932"

   strings:
      $hex_string = { 1a3b4dd8771d0375cc2b55ec015dec8d0c1e894db48bd98a0c32880e463bf375f6eb298b45cc8b7dd8660f1f4400008a0c0242880c0633c9463bd70f44d183eb }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
