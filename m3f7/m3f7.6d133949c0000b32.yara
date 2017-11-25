
rule m3f7_6d133949c0000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f7.6d133949c0000b32"
     cluster="m3f7.6d133949c0000b32"
     cluster_size="6"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="clicker faceliker html"
     md5_hashes="['012e75a19b1c7c271c9b1b0cd00d78bf','12ad4ce943d1042a5ee1ae453293c4c5','c9ed3b48f6c81a9aa4563bd71bfcef51']"

   strings:
      $hex_string = { 28274174747269627574696f6e3127292c207b7d2c2027646973706c61794d6f646546756c6c2729293b0a5f5769646765744d616e616765722e5f5265676973 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
