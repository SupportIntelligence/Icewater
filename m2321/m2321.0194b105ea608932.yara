
rule m2321_0194b105ea608932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.0194b105ea608932"
     cluster="m2321.0194b105ea608932"
     cluster_size="26"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="johnnie riskware uvpm"
     md5_hashes="['00ccf1a8005606d2647182f095a6a8fd','17cb4e94a8e28cd3ebdb76a9ef727d93','a9ef22d39b3b17d29ee9b731eb70528f']"

   strings:
      $hex_string = { 59b27421c075be2d03f79208d8cfa3a1d052d96ecbc840460d0681414bb36dfee65a075e353d8f42ea30874af383166b0fccdd4518fa0b2b9dab96f2c151ca47 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
