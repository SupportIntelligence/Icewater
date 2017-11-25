
rule m3f7_599b33c9c8000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f7.599b33c9c8000b32"
     cluster="m3f7.599b33c9c8000b32"
     cluster_size="6"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="likejack faceliker script"
     md5_hashes="['0265e5267c1a18f70838a76fc3be685e','4688364210b8525e24a797289cea4a43','dd87bc2a99f071d927e4ca471bff401b']"

   strings:
      $hex_string = { 4e78597041573143635676684b5f647068374b563065526e73696f6f775a736c55584433586e455632594974715a31546b67334a4d4265546d30754661272077 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
