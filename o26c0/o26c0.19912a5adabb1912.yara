
rule o26c0_19912a5adabb1912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26c0.19912a5adabb1912"
     cluster="o26c0.19912a5adabb1912"
     cluster_size="10"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="graftor kryptik malicious"
     md5_hashes="['0431ea05f8a7e6f5d59bd609ea4392699e71765e','4f7b4736b803bb6f995459d09dfcb427dced11ac','fe0401cb59e4dd6ba9b5be3409ce8c01808957c3']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26c0.19912a5adabb1912"

   strings:
      $hex_string = { 35c81793764c728782007ab4b09027630fea4812155e13b9dcc18f9b9aba317c26bfa6daa58146435fa8450066b3163ebd08f38a4f9dc406974b7807699feddb }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
