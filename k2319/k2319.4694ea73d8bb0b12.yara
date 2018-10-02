
rule k2319_4694ea73d8bb0b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.4694ea73d8bb0b12"
     cluster="k2319.4694ea73d8bb0b12"
     cluster_size="12"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script browser"
     md5_hashes="['7955f9f1335fcd3a7c50c16ede2d8bc238c73af6','336f69228eb5118585d76631b3ab4bccaf1102c9','3bd8d6ccdca572dc95f626c22f99ee0bb38d8ca7']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.4694ea73d8bb0b12"

   strings:
      $hex_string = { 2e3333364533292929627265616b7d3b766172205a376e38563d7b27433331273a342c27553231273a227061222c276f3756273a66756e6374696f6e28472c78 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
