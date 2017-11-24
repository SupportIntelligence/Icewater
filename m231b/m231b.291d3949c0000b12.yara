
rule m231b_291d3949c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m231b.291d3949c0000b12"
     cluster="m231b.291d3949c0000b12"
     cluster_size="8"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="fakejquery script classic"
     md5_hashes="['2ff4dc267bcfed69d96efe0af14d08fb','308af310e17c15385ea63732410ee5f8','f300480ed3ef16fcf2cbff69f73a30a2']"

   strings:
      $hex_string = { 3a2f2f676f6c64656e776c3478346478622e636f6d2f6a732f6a71756572792e6d696e2e70687027202b20273f6b65793d62363427202b20272675746d5f6361 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
