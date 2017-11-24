
rule j3f0_25a6e1651ee31132
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3f0.25a6e1651ee31132"
     cluster="j3f0.25a6e1651ee31132"
     cluster_size="29"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="graftor malicious malob"
     md5_hashes="['067463662621f23ddbe722a148a6472c','1239e9c0ce0cf535bbe6f58bdac940e6','9f7a37a561bae7ee56e47bd4522b433b']"

   strings:
      $hex_string = { b158045e09801868201523bf143c1251c4b048d2445e3101be9e24c0706c38404dec0e03bc6dfd03c422605cb40ea026619c680c40500058f07919d5064de4a1 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
