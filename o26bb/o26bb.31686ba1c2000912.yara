
rule o26bb_31686ba1c2000912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26bb.31686ba1c2000912"
     cluster="o26bb.31686ba1c2000912"
     cluster_size="682"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="downloadsponsor malicious unwanted"
     md5_hashes="['f7470752b925f30db61af11f7bcbd5e9762d1443','a6e1053da3676e408fe1a8fefc7098c44a806958','32b13b3767196be1f55116067709c581170cead5']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26bb.31686ba1c2000912"

   strings:
      $hex_string = { 261b2db3d2949d012012a9871a824d2f3da167efdcb022b83914a6fcc91fb47a625f8ed1470c44582e1c61cd03bf16594c63cf8db7319673084bc217770ea7ed }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
