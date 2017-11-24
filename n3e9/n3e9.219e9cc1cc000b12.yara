
rule n3e9_219e9cc1cc000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.219e9cc1cc000b12"
     cluster="n3e9.219e9cc1cc000b12"
     cluster_size="273"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="installerex installrex adload"
     md5_hashes="['13b109194f01884e0e3851936d96e8bc','19bf2bb2495518ab90a4ad8483a3f0c4','6fef69013a568dc5a12a447db1d3a719']"

   strings:
      $hex_string = { 6b1e101daf69fdf3307952e90d018941906ccaaa9f398cbabbed62dd1ab92a9eefcf206d347256f8db3ebdbf3a8a8150269cd53da82fcd08974865147594c087 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
