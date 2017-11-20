
rule m2321_0194a085ea608932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.0194a085ea608932"
     cluster="m2321.0194a085ea608932"
     cluster_size="13"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="johnnie riskware uvpm"
     md5_hashes="['1a9ccb35ff8260b37895c53c286c4989','36aa13660bafe3eb3dc5f6ed9930feec','e98f60da56743123b375f55ce234d460']"

   strings:
      $hex_string = { 59b27421c075be2d03f79208d8cfa3a1d052d96ecbc840460d0681414bb36dfee65a075e353d8f42ea30874af383166b0fccdd4518fa0b2b9dab96f2c151ca47 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
