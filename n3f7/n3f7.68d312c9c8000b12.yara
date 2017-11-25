
rule n3f7_68d312c9c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f7.68d312c9c8000b12"
     cluster="n3f7.68d312c9c8000b12"
     cluster_size="12"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['08c66d0d836460a2d41d63f08dc8b1a3','156cf6e8644a558bc050329f1b4f78b5','c954d701fcf6332a7c85d90a0746eb38']"

   strings:
      $hex_string = { 44333638374644414439364438343343303546373342374336453042343133373043314139303536384132313936393732373932453845453242463130423534 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
