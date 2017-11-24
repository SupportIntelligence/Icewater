
rule o2321_19922122d982d115
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o2321.19922122d982d115"
     cluster="o2321.19922122d982d115"
     cluster_size="107"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="optimizerpro speedingupmypc unwanted"
     md5_hashes="['006875cd271bc0558acb531e4c5b374f','007c157f881f5646b6a5e50b24b861b3','2763a9a866e3714db235486bdea78b3d']"

   strings:
      $hex_string = { 5d0780a87a1db5bde892349aade10d9167aa86a40cfbc884ae174648c0dc4ece22990fdec60b58dd938d903332b114e76910c58c7c37faebd1a6237eed65d92a }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
