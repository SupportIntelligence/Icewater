
rule m2319_4b191ec1c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.4b191ec1c8000b12"
     cluster="m2319.4b191ec1c8000b12"
     cluster_size="14"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="likejack faceliker script"
     md5_hashes="['033c38d27b539a4e7547809969b25fae','50c2c46c809a3521bbaeb9f5c177dc36','f20306e204793cef3b1c545a5b765008']"

   strings:
      $hex_string = { 722e636f6d2f7265617272616e67653f626c6f6749443d3536393431373533303839383534343331313326776964676574547970653d426c6f67417263686976 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
