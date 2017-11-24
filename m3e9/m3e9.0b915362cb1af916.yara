
rule m3e9_0b915362cb1af916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.0b915362cb1af916"
     cluster="m3e9.0b915362cb1af916"
     cluster_size="4"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="scar scudy zusy"
     md5_hashes="['306ebac9cd6aed45b7bd13b279b103fb','aa546b3a4e2f77df12ba457756b01aec','f8021e98072ab8f1a54e5c28d8ede7bb']"

   strings:
      $hex_string = { 11da6b34a5f5b5b01fc88feb6704031470c089a08c2cefb985ce0ee555c3634b46a5d11c8a294597ac3917d313ba1acd1d7a1252288b184e50cf615bc6f1414f }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
