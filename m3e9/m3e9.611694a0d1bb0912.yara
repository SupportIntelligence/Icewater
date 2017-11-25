
rule m3e9_611694a0d1bb0912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.611694a0d1bb0912"
     cluster="m3e9.611694a0d1bb0912"
     cluster_size="32"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="allaple rahack allaplet"
     md5_hashes="['15b04987525fc14d74552d21a8296176','2258a11d390564d01d7872db6ad84a2a','ab8434478bd530cd4b3c3d8a72aca1dd']"

   strings:
      $hex_string = { 62fb7cf58e079811aa23a43db64fc059d26bec65fe7708811a9314ad26bf30c942db5cd56ee778f18a03841d962fa039b24bcc45de57e861fa73f48d069f10a9 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
