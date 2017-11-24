
rule j3f9_11ee7e0d9ee31512
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3f9.11ee7e0d9ee31512"
     cluster="j3f9.11ee7e0d9ee31512"
     cluster_size="34"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="graftor malicious malob"
     md5_hashes="['024f0c45f16ad6e3789632655625a5a6','03d2677a19a94766e069be512b5b93dc','65f72c4918b1b504af0dbc654c2755d1']"

   strings:
      $hex_string = { b158045e09801868201523bf143c1251c4b048d2445e3101be9e24c0706c38404dec0e03bc6dfd03c422605cb40ea026619c680c40500058f07919d5064de4a1 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
