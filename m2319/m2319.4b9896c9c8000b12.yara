
rule m2319_4b9896c9c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.4b9896c9c8000b12"
     cluster="m2319.4b9896c9c8000b12"
     cluster_size="6"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="likejack faceliker script"
     md5_hashes="['2fa8825420932211ffcfa3f17b499ef1','a62719b093571e498ec8134bf71871b5','fee53e1b6c37733c6ea21b86e65e0754']"

   strings:
      $hex_string = { 77205f576964676574496e666f2827426c6f674172636869766531272c2027736964656261722d72696768742d31272c206e756c6c2c20646f63756d656e742e }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
