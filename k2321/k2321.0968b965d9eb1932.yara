
rule k2321_0968b965d9eb1932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.0968b965d9eb1932"
     cluster="k2321.0968b965d9eb1932"
     cluster_size="4"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus conjar autorun"
     md5_hashes="['0f45f5ee3f04c607ff2a79a5022e3f6b','75a3f815ed477e99253ecaa1079322d0','c9ccd61a1972af366bdeeb5732f875d4']"

   strings:
      $hex_string = { ad2d994e981a92d186e163a1413cb17a8bb826dfcc1dd6a9eb52f34a101d961f76e712395d1ce437a4eca631259b469418b506ce78e143b65b59fc6be2bbd86e }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
