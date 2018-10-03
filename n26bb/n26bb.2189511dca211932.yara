
rule n26bb_2189511dca211932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bb.2189511dca211932"
     cluster="n26bb.2189511dca211932"
     cluster_size="46"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="symmi malicious virut"
     md5_hashes="['4da94b72c252c0e07a445e5a656a311d5e39908f','d9cb151779cc54ebc5fe833df9a71080c0005690','67f3f6c11f49425d61b93e9facb9130874ba2b3d']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bb.2189511dca211932"

   strings:
      $hex_string = { 696465ff615d5dff5b5555ff564e4efe4f4849f4433e3ddd302d2bb11a191b7b0e0f1260101112621518197a1b20229d1f272ac325292bd11619195180808000 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
