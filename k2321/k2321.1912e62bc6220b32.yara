
rule k2321_1912e62bc6220b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.1912e62bc6220b32"
     cluster="k2321.1912e62bc6220b32"
     cluster_size="5"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="mikey nsismod siggen"
     md5_hashes="['0735d489c693316de803934dffca3673','3fd2836451364decd0b4083cbd8ca17d','f0f87885b0d3768545f7cacc9ce2aba1']"

   strings:
      $hex_string = { a69a7b077a8d2b0dd7379305d6639dcf3f885f71f89e6b08a967bfaa0c9887de34be57a731f329e00f6f722dc2975133da2afbcde38e85ec75a569d813741611 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
