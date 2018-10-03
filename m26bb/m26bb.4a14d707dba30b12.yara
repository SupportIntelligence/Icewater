
rule m26bb_4a14d707dba30b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m26bb.4a14d707dba30b12"
     cluster="m26bb.4a14d707dba30b12"
     cluster_size="1161"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="codiby generickd malicious"
     md5_hashes="['2d45f37b080c9e676b080e27a62e1465a78a8bd7','d4c1b72aea1eccf2f47e022f28284bc316165a88','83c3c696ac0644c850f6cd7ccca5f8677461d4a7']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m26bb.4a14d707dba30b12"

   strings:
      $hex_string = { fd80370f6575c90a82cec66f1ffc8539d1d548285378ec09dce99d8426068318df175800072cca70540b921b0390f6d03257e3f4eebe6b3579a8a95a6631688e }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
