
rule o26c0_599aa254db9b1912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26c0.599aa254db9b1912"
     cluster="o26c0.599aa254db9b1912"
     cluster_size="4"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="graftor kryptik malicious"
     md5_hashes="['78cdcbf0a26ffd0d4eb758136003158bbea6d90d','4c8a8837be7ba71d112dc44340fb498706951be4','1ae4c30d6981a0bc27a541f8cf8d3be43ac03b25']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26c0.599aa254db9b1912"

   strings:
      $hex_string = { d4c6da7b6575897699a343b21fe735f2724bcc82aee0463d9a507dcb5a79db902a6e324fe441e2548def3307e6e5f9ac066f7c93edd3273a2404c7475b2f1918 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
