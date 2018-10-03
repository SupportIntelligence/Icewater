
rule o26bb_31686ba1c8001312
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26bb.31686ba1c8001312"
     cluster="o26bb.31686ba1c8001312"
     cluster_size="2415"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="downloadsponsor malicious unwanted"
     md5_hashes="['f60acdad8583b57ec5d3379d9b6d7bf3bdf82739','763c3752191ac5bce1fd28a5f04045c671eeb0cb','ad623d5e20116fa2b91240703f7e76003a01cc93']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26bb.31686ba1c8001312"

   strings:
      $hex_string = { 261b2db3d2949d012012a9871a824d2f3da167efdcb022b83914a6fcc91fb47a625f8ed1470c44582e1c61cd03bf16594c63cf8db7319673084bc217770ea7ed }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
