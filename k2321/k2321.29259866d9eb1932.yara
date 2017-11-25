
rule k2321_29259866d9eb1932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.29259866d9eb1932"
     cluster="k2321.29259866d9eb1932"
     cluster_size="7"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus symmi vbkrypt"
     md5_hashes="['28a7960d5faf85dd65f358e8c0c8d280','2ddca4354014001fb8fc0d39257aad66','fde03a7fa5ca5187f1bfb66b8aec4069']"

   strings:
      $hex_string = { c96a5445aed09193d1bed9688fecdd783b1cbbf68774971417eaf5a80023d3e63a3a32b5eed694021875b76ce1f2cf9b53487c5aaf86b679dd27357dc2476415 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
