
rule m3f7_191a53c9c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f7.191a53c9c8000b12"
     cluster="m3f7.191a53c9c8000b12"
     cluster_size="10"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="likejack faceliker script"
     md5_hashes="['2ea8011eaaa6135035198a6d85966c0d','459cec7832f54373343dcacac41d406d','d4f95ce130c84af7b5fcde38071b1d50']"

   strings:
      $hex_string = { 78507745584751596c3253384e486633525f762d3049674c596173767a3942524f365066324d5471464d7036574e41366f33697a72384a4f784e44626e333561 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
