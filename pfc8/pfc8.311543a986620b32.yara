
rule pfc8_311543a986620b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=pfc8.311543a986620b32"
     cluster="pfc8.311543a986620b32"
     cluster_size="124"
     filetype = "application/zip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="androidos riskware smsreg"
     md5_hashes="['017034ea1d96cc17d3367c0ba8147e09','04bab4fb0a6da370d7ea8d35e5346435','228282d4c5896f142a54453928f8e3db']"

   strings:
      $hex_string = { b0da0075531259fccb0430a0a4741880724b7767b13227bbe960a1bf05515a64100150d29af91e733a9031a37e92af8e38d9ef87fa8815d0cd284723ce4f950c }

   condition:
      
      filesize > 4194304 and filesize < 16777216
      and $hex_string
}
