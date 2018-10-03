
rule o26bb_35686ba1c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26bb.35686ba1c8000b12"
     cluster="o26bb.35686ba1c8000b12"
     cluster_size="734"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="downloadsponsor malicious unwanted"
     md5_hashes="['23f4239ed96298a9b79b0f47cb40eb60e76a5ea8','dfc0d78d7fc503fdbd1b6c6ad19d21175835de29','ba4218e9e4d517c03a097170f64cdffabd9b8fa4']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26bb.35686ba1c8000b12"

   strings:
      $hex_string = { 261b2db3d2949d012012a9871a824d2f3da167efdcb022b83914a6fcc91fb47a625f8ed1470c44582e1c61cd03bf16594c63cf8db7319673084bc217770ea7ed }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
