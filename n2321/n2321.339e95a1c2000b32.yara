
rule n2321_339e95a1c2000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2321.339e95a1c2000b32"
     cluster="n2321.339e95a1c2000b32"
     cluster_size="41"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="startpage zusy adsearch"
     md5_hashes="['00cf46df4b6be0d5ea5f662840c03d62','038b41c34c8c9825fe584e89930e08e4','4dfcd150738289e8ddff1c392ec39379']"

   strings:
      $hex_string = { 2ca0b7c4820be9f57a70f3edd017eadaab373fd69f2b87474558a8c816c99c512f8df28625b03ab5354b68cd8ff1ba7649b9cbcaae33d3e7e1dda69826afb31b }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
