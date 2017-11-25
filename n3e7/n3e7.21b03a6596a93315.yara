
rule n3e7_21b03a6596a93315
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e7.21b03a6596a93315"
     cluster="n3e7.21b03a6596a93315"
     cluster_size="9"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="downloadsponsor malicious unwanted"
     md5_hashes="['470787f4628d7b1dc57666053687095d','5267e6e70fe3d5cd306de4c631a8e1d8','fb6e2974734bc6f6932b992bfcd29057']"

   strings:
      $hex_string = { 261b2db3d2949d012012a9871a824d2f3da167efdcb022b83914a6fcc91fb47a625f8ed1470c44582e1c61cd03bf16594c63cf8db7319673084bc217770ea7ed }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
