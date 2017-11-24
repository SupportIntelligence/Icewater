
rule k2321_2b16ed6d949b0912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.2b16ed6d949b0912"
     cluster="k2321.2b16ed6d949b0912"
     cluster_size="14"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="tinba emotet zusy"
     md5_hashes="['05047f7bb188dc034458672c776c32ca','19d26a13c7de9467ffba69efff1d40d7','f653edea2ae43663ea85ecff9f214a1d']"

   strings:
      $hex_string = { c7488e03f81cd2fb8d50152344c008334c3f6aec54e83b726d44ce7101df1e9a5b5af763984e64d19b92a3b791371b617ad334bed9ea9e215f8ec6dd14025942 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
