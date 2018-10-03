
rule o26bb_594a4e6adee30932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26bb.594a4e6adee30932"
     cluster="o26bb.594a4e6adee30932"
     cluster_size="19"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="dealply malicious adwaredealply"
     md5_hashes="['3cda6fecfdacbea0bfe6aa302ac3d8732844f877','453a6c1bd1b66a9c6ac6c7c0d9d68be5db800cb6','fe16a5bc3b7cbb6b941ef21fe9bfa902bf736653']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26bb.594a4e6adee30932"

   strings:
      $hex_string = { 55544638537472696e67e9fd0200fc2340000a0d52617742797465537472696e67ffff020000142440001408504c6f6e67496e749c1040000200282440001405 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
