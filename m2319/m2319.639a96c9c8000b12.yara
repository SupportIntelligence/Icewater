
rule m2319_639a96c9c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.639a96c9c8000b12"
     cluster="m2319.639a96c9c8000b12"
     cluster_size="4"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="likejack faceliker clicker"
     md5_hashes="['44bdc38531787a31419680afd19a118c','67a5f09edcf802cead4aaacd84286426','8ac340d8b9f5b5e698635b20ea279643']"

   strings:
      $hex_string = { 2e636f6d2f7265617272616e67653f626c6f6749443d3638373231373038313637313339353634393826776964676574547970653d426c6f6741726368697665 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
