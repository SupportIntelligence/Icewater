
rule j3f0_25ee7a0d9ee31532
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3f0.25ee7a0d9ee31532"
     cluster="j3f0.25ee7a0d9ee31532"
     cluster_size="18"
     filetype = "PE32 executable (GUI) Intel 80386 (stripped to external PDB)"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="graftor malicious malob"
     md5_hashes="['0e4be78e4e72ed95b89ae04fc0f8b12c','151449a813292b6a40f0f456c8ddb184','de4dc0055f870b124f8903ce1751a2c9']"

   strings:
      $hex_string = { b158045e09801868201523bf143c1251c4b048d2445e3101be9e24c0706c38404dec0e03bc6dfd03c422605cb40ea026619c680c40500058f07919d5064de4a1 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
