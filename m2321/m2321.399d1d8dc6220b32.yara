
rule m2321_399d1d8dc6220b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.399d1d8dc6220b32"
     cluster="m2321.399d1d8dc6220b32"
     cluster_size="7"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="otwycal wapomi vjadtre"
     md5_hashes="['1ef7c0ad9caaf4fb986e912c1507a21d','1f92b734385cfb1cdd23458f646e8018','d5a89e171974f2cf47817df43134acd5']"

   strings:
      $hex_string = { 5f479da4d72d6d87b5d49c9554c898c09985c60a4da9b7c941fa4940a8e5001a4ffe0150d06fa5b626738dcf7b25bb83ba3914d891920306e3247f20688a15fd }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
