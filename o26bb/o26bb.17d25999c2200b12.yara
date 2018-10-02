
rule o26bb_17d25999c2200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26bb.17d25999c2200b12"
     cluster="o26bb.17d25999c2200b12"
     cluster_size="37"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="gamehack malicious unsafe"
     md5_hashes="['d2aef40fb7726bd3fd169d60114a681519f5553e','d63a15c72ab948240345cb6a75c6f2392251291d','3a74eefb937ad98ceda962494dc7f6cc27d64b4c']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26bb.17d25999c2200b12"

   strings:
      $hex_string = { 897c24504c63fd4f8d24bf49c1e7040f2974244049c1e4034983c7084b8b042f4c2bf03bef7d420f57f685ed792133db85ff7e390f1f4400008bd3488bcee8b6 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
