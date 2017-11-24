
rule m3e9_12999bc9c8000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.12999bc9c8000b32"
     cluster="m3e9.12999bc9c8000b32"
     cluster_size="26"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob virux"
     md5_hashes="['009a2f85a5659490baa7030f8f577435','02956d05fe9d56594cfca9496eeb44d9','e31c2e4febbca224bba944e766965a42']"

   strings:
      $hex_string = { 00598945ec8365fc0085c0741f68d9a800016847520001578d58046a0c538938e82c5600008bc38b5d08eb0233c0834dfcff33ff397e18894614897df00f8e88 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
