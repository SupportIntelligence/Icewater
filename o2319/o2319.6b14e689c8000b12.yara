
rule o2319_6b14e689c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o2319.6b14e689c8000b12"
     cluster="o2319.6b14e689c8000b12"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="script coinminer miner"
     md5_hashes="['122c2d00194afe67ea4ef1f4183508b929ea21ba','223bed586949e809a857acab78a067e67318a356','cfa9fc2c6a795d8b3b679066c1672f8653301d0c']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o2319.6b14e689c8000b12"

   strings:
      $hex_string = { 3f203835303a203132353b090d0a092f2f6966282428272e6e65637461722d626f782d726f6c6c27292e6c656e677468203d3d2030292073657454696d656f75 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
