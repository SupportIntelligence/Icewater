
rule o2321_49910ac4fa630912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o2321.49910ac4fa630912"
     cluster="o2321.49910ac4fa630912"
     cluster_size="6"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut graftor shodi"
     md5_hashes="['11f209cf000fea16134ba0f5dd9f393d','1b946245b2347bfe2858e43e05141a8c','d8939968372587bc7d40ee0ec9164097']"

   strings:
      $hex_string = { 4a2b4e4c76ee842f817c2050bf28302962b13cab542ea73efba0cfa1531ea90452f9851a8c36a47d3717cb997eb995929627beb7e4144ddd5e58a3906c9e7397 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
