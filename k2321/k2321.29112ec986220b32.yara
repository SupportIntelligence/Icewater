
rule k2321_29112ec986220b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.29112ec986220b32"
     cluster="k2321.29112ec986220b32"
     cluster_size="12"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="brontok email pazetus"
     md5_hashes="['04124510fa8fd2d8fbe9d1a0e6eb00a6','5aa517df5b08716113b236435af391b5','fcdcd1eb5c5764ad3d5c7184f1fd31e4']"

   strings:
      $hex_string = { 64bfdc189ee8164d853ccad9c27cbd8ab2f31ad628ed33b666c59d4d0b5d5b7a1091358cf752b13e88cc0c82983662c3530438b0342957307bbcf011588f7efd }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
