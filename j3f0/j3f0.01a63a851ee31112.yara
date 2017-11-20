
rule j3f0_01a63a851ee31112
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3f0.01a63a851ee31112"
     cluster="j3f0.01a63a851ee31112"
     cluster_size="11"
     filetype = "PE32 executable (GUI) Intel 80386 (stripped to external PDB)"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="graftor malicious generik"
     md5_hashes="['03f00c94c6146fa0b07ada10a5fa805b','167b746a3cb2817a6dcb8ec5b0c9759b','f275bdfa32e86cf8bd3af3c9fc746365']"

   strings:
      $hex_string = { b158045e09801868201523bf143c1251c4b048d2445e3101be9e24c0706c38404dec0e03bc6dfd03c422605cb40ea026619c680c40500058f07919d5064de4a1 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
