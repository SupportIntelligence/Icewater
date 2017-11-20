
rule m3e9_129993a9ca000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.129993a9ca000b32"
     cluster="m3e9.129993a9ca000b32"
     cluster_size="14"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob virux"
     md5_hashes="['01ebb3a72bf0782e84643d41178e6f5b','33d2fbe558dd7ccec3123b166b3a72f2','fe3e1413b35f29227893bdfc4aae88cd']"

   strings:
      $hex_string = { 00598945ec8365fc0085c0741f68d9a800016847520001578d58046a0c538938e82c5600008bc38b5d08eb0233c0834dfcff33ff397e18894614897df00f8e88 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
