
rule m3e9_7d449ca54da6e3b3
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.7d449ca54da6e3b3"
     cluster="m3e9.7d449ca54da6e3b3"
     cluster_size="40"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus chinky vbkrypt"
     md5_hashes="['091618b97b02780a5d05ff84c0c35c5a','0a314c0ab73e806048ad0ddd825b56fc','c2feaa08840e1466c9ba759ea015f6ec']"

   strings:
      $hex_string = { 51543bc3dbe27d0e6a5468887640005750e8e749fdff8d45d4508d45d8506a02e83a4bfdff83c40c66ff463ceb856828f04200eb21f645fc0474088d4ddce8c8 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
