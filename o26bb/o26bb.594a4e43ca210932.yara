
rule o26bb_594a4e43ca210932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26bb.594a4e43ca210932"
     cluster="o26bb.594a4e43ca210932"
     cluster_size="51"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="dealply malicious biplz"
     md5_hashes="['3ab972a4d250411ae1e5f3f0a0cb09cda83e9f40','16b1aa9691951e8c505bba6ef93297ac5108a8c7','29d4c1e94a671b3f081e047db1869f8caa6cd8b8']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26bb.594a4e43ca210932"

   strings:
      $hex_string = { 0bb00bb00bb00be00fd909e0172f042f042f042f042f042f042f042f043100f0175100001810182018300d31000a0230184018501821183100f0175100601870 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
