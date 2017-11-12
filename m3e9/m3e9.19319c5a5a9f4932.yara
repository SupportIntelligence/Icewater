
rule m3e9_19319c5a5a9f4932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.19319c5a5a9f4932"
     cluster="m3e9.19319c5a5a9f4932"
     cluster_size="3"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="jadtre qvod wapomi"
     md5_hashes="['ebd0b7744e2fcc63813c582308451ea2','f9dbc5a6cbf3025c8079a38d79aadc78','fb6783c1f6d0bdead9691d32ecd9e31b']"

   strings:
      $hex_string = { a3565d54009b481665ee9757d629864256138abe74ee50067d389ead9caa6115a5d3b0881614d0cb8a60a22948363b2b98bb32ef7131228e096c9e69dc6121c1 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
