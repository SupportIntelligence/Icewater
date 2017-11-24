
rule m2321_0b915362c91af916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.0b915362c91af916"
     cluster="m2321.0b915362c91af916"
     cluster_size="34"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="scar zusy scudy"
     md5_hashes="['054574b3017815565d86a7fc9d56e3fa','069ce1243909a84942f679a2a9c1ca13','6073f6aa1b5a62b6ae1b3d03021471cd']"

   strings:
      $hex_string = { 11da6b34a5f5b5b01fc88feb6704031470c089a08c2cefb985ce0ee555c3634b46a5d11c8a294597ac3917d313ba1acd1d7a1252288b184e50cf615bc6f1414f }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
