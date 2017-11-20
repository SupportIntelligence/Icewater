
rule j3f0_2567e12c1ee30912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3f0.2567e12c1ee30912"
     cluster="j3f0.2567e12c1ee30912"
     cluster_size="32"
     filetype = "PE32 executable (GUI) Intel 80386 (stripped to external PDB)"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="graftor malicious malob"
     md5_hashes="['03ecb47f11c1dbbfc0fdc8c18d1db0db','1c4c99663ad6e5b62bdd3d37da067d6c','6db93b2535f5dc81159512d6f14ad135']"

   strings:
      $hex_string = { b158045e09801868201523bf143c1251c4b048d2445e3101be9e24c0706c38404dec0e03bc6dfd03c422605cb40ea026619c680c40500058f07919d5064de4a1 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
