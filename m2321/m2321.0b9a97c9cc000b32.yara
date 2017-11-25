
rule m2321_0b9a97c9cc000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.0b9a97c9cc000b32"
     cluster="m2321.0b9a97c9cc000b32"
     cluster_size="6"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="otwycal wapomi vjadtre"
     md5_hashes="['056a117b48923653dc919b384a53cebd','16ddf687f971a69b5c01db433001d3e9','bf3666edef4d860dc93f9f0ca9963e36']"

   strings:
      $hex_string = { e75417592bed3b4fb43e4a9598eaa94449a68028786de90245e0b37bb8accf8e9dbdd0a426bfc5e8a0d33f1cca7913cd84abdbb0c48f7139ce7d20c91f5e8cb6 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
