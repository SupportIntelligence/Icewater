
rule m26bb_4dc8be42c9bb2593
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m26bb.4dc8be42c9bb2593"
     cluster="m26bb.4dc8be42c9bb2593"
     cluster_size="3157"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="linkury generickd rootkit"
     md5_hashes="['12d7cfbd160886935745926a2e1c89f45d162904','820188044effe9f8e97f635ff0ed3e1983a75f08','e39e43622b19215a36d310769b645b1fcfd3338c']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m26bb.4dc8be42c9bb2593"

   strings:
      $hex_string = { 0fb6442434f7d81bc023c150ff7704ff1510f042005f5d5b83c41cc20c00515355568bf183cbffbdf8bb4300395e047511807e1400745a8d461e8bcd50e87ed5 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
