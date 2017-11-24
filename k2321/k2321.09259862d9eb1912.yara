
rule k2321_09259862d9eb1912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.09259862d9eb1912"
     cluster="k2321.09259862d9eb1912"
     cluster_size="4"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus symmi vbkrypt"
     md5_hashes="['0052f418ad4680284b65641039ec6954','09e6e1301e73d3f6077dbe38bd3cf79c','52cec0b59b6969660f91afbfc0600b9a']"

   strings:
      $hex_string = { c96a5445aed09193d1bed9688fecdd783b1cbbf68774971417eaf5a80023d3e63a3a32b5eed694021875b76ce1f2cf9b53487c5aaf86b679dd27357dc2476415 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
