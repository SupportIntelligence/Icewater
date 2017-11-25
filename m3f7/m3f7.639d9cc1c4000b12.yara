
rule m3f7_639d9cc1c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f7.639d9cc1c4000b12"
     cluster="m3f7.639d9cc1c4000b12"
     cluster_size="9"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="likejack faceliker clicker"
     md5_hashes="['1fc6a6cf498743cd90f3141929b46eab','4e10260aeed201eb0033afa8958873c7','ded9207e4a6779eee86a4fa838d5a089']"

   strings:
      $hex_string = { 722e636f6d2f7265617272616e67653f626c6f6749443d3638373231373038313637313339353634393826776964676574547970653d426c6f67417263686976 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
