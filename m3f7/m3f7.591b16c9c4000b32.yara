
rule m3f7_591b16c9c4000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f7.591b16c9c4000b32"
     cluster="m3f7.591b16c9c4000b32"
     cluster_size="40"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="likejack faceliker clicker"
     md5_hashes="['0137e9b5a3372b64db7d84000e1399d0','01daeacd8e83cd8afc640a8bbba5b835','7b69aa2e84dcb25a44f5e49bd54df75b']"

   strings:
      $hex_string = { 456c656d656e7442794964282748544d4c3227292c207b7d2c2027646973706c61794d6f646546756c6c2729293b0a5f5769646765744d616e616765722e5f52 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
