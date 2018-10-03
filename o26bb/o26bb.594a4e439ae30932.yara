
rule o26bb_594a4e439ae30932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26bb.594a4e439ae30932"
     cluster="o26bb.594a4e439ae30932"
     cluster_size="179"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="dealply malicious susp"
     md5_hashes="['1cef25108ab52359d248e90a35bc5ca1f6541617','3ff631e2a8f254c8dfa723a672801fb2b5fb5ef4','a47aa929564724688de4800fcba5e928d1cafe97']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26bb.594a4e439ae30932"

   strings:
      $hex_string = { 55544638537472696e67e9fd0200fc2340000a0d52617742797465537472696e67ffff020000142440001408504c6f6e67496e749c1040000200282440001405 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
