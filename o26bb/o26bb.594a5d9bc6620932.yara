
rule o26bb_594a5d9bc6620932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26bb.594a5d9bc6620932"
     cluster="o26bb.594a5d9bc6620932"
     cluster_size="6"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="dealply malicious agen"
     md5_hashes="['09e47f3b9d55304bfe0ae84bca912ad0b1392aad','c6c29c6b1b777ee8f8603d5fb078cd12c2e11d36','b7ad1c2e3aa1c71beadb9d80d3f41c92cebaf48d']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26bb.594a5d9bc6620932"

   strings:
      $hex_string = { 55544638537472696e67e9fd0200fc2340000a0d52617742797465537472696e67ffff020000142440001408504c6f6e67496e749c1040000200282440001405 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
