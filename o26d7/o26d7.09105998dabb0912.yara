
rule o26d7_09105998dabb0912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26d7.09105998dabb0912"
     cluster="o26d7.09105998dabb0912"
     cluster_size="108"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="razy amonetize kryptik"
     md5_hashes="['3717fb13a9288a9e8f773a373babd056672952b9','2eaddb191e6776a8557b6cdbcf0447d4002ab6b9','c9e2e392b558154228f2c5b4b4e4c90ef316b0f8']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26d7.09105998dabb0912"

   strings:
      $hex_string = { 3ec0fb496c80855989123d46b57f745ed5d7d6d34dca538dea568d7310355c49ee040b7e72318d4380578df3820d48046687974200008d821f8b400288c0fb44 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
