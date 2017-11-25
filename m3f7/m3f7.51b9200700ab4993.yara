
rule m3f7_51b9200700ab4993
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f7.51b9200700ab4993"
     cluster="m3f7.51b9200700ab4993"
     cluster_size="145"
     filetype = "application/octet-stream"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['00a8e6e80945d98de495619f5c9aeab4','01094c334a29c7732874b8449186bb03','16d5ccf92c387f4592768ee28747cc8f']"

   strings:
      $hex_string = { 32248657d6923d69cc60f48580373f6d3fde8f4eb79f59c3a47ceb604ddfc9055f6b878d22672c3fe3560e2f16413c5e75f45b3f63b676b56886780399a30884 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
