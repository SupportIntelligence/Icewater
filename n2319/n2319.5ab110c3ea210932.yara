
rule n2319_5ab110c3ea210932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2319.5ab110c3ea210932"
     cluster="n2319.5ab110c3ea210932"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="script miner coinminer"
     md5_hashes="['0aa2eb2990a07896ce3473b5a496c43f5b0e53a5','39c8b6eac3af9b1e19251be842ffa6fb6e7757d3','81920b0e19650bdac7ac04306d08f5f63f63f961']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n2319.5ab110c3ea210932"

   strings:
      $hex_string = { 2e636f6e63617428617267756d656e7473295b305d5b305d20213d3d20313b0a20207d2928312c32290a0a202069662028434f4e4341545f415247554d454e54 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
