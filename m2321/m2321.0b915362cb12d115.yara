
rule m2321_0b915362cb12d115
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.0b915362cb12d115"
     cluster="m2321.0b915362cb12d115"
     cluster_size="50"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="scar zusy scudy"
     md5_hashes="['0c1a1ac1342b9a6aed794be2231ceaa0','0ec9d40b4b40de99fc373c94ba969c91','6662007e5a6617cd03e4f60c991961f6']"

   strings:
      $hex_string = { 11da6b34a5f5b5b01fc88feb6704031470c089a08c2cefb985ce0ee555c3634b46a5d11c8a294597ac3917d313ba1acd1d7a1252288b184e50cf615bc6f1414f }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
