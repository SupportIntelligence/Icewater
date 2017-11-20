
rule m2321_71b3651efa210912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.71b3651efa210912"
     cluster="m2321.71b3651efa210912"
     cluster_size="110"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="hacktool kmsactivator kmsauto"
     md5_hashes="['000cef3d36c3ea0630ab4daa1eab81ad','000d3de01c6565c2244861274ec42afb','23cf2cc9e79e396e58e3c7a9e9832e30']"

   strings:
      $hex_string = { 204faeabb3d9431e97413113ee8cd955958339b9f064e3f4a49878e14e0dbc797ad2d829f1c2ed1060469d510366bb8d886d00ec85803e365e4c8ba05f09e8c9 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
