
rule k2319_112c78e1c2000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.112c78e1c2000932"
     cluster="k2319.112c78e1c2000932"
     cluster_size="12"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik expkit script"
     md5_hashes="['56ac01218334fb495aed3af7e88cfad6fcaf7cfe','560962f86aba582e9400b4cebe45cf9021edcbc6','fe04124fe4aee79f3437c7f7200bb28607642264']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.112c78e1c2000932"

   strings:
      $hex_string = { 756e646566696e6564297b72657475726e204b5b765d3b7d766172206f3d28363c3d2835342e343045312c31332e293f2833302c30786363396532643531293a }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
