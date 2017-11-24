
rule k2321_09685b2199eb1912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.09685b2199eb1912"
     cluster="k2321.09685b2199eb1912"
     cluster_size="4"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus razy autorun"
     md5_hashes="['59ec10f53cb86aadb9398830421b1f06','5a1f941b582e97b317d6b40cfc287593','fcb39eb841adbb74e85d42889679f80d']"

   strings:
      $hex_string = { d183a482a5bd16558b60abcadb91c362b771241e4642fce7ed4388ffb0417ade6efa728af80fb3c73c330c905ed768ceb9e993b5aec91c3d1b322550de9b1103 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
