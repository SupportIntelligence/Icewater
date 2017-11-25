
rule m3f7_191871a1c2000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f7.191871a1c2000b12"
     cluster="m3f7.191871a1c2000b12"
     cluster_size="13"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="likejack faceliker clicker"
     md5_hashes="['075e5f02a8ae4957f602b2bfc01a9071','08e37be8d83f849d66badb30e65db2da','d61e48d9fc2d7ee128807345a009a2cf']"

   strings:
      $hex_string = { 78507745584751596c3253384e486633525f762d3049674c596173767a3942524f365066324d5471464d7036574e41366f33697a72384a4f784e44626e333561 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
