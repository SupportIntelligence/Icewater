
rule n3e9_219c9cc9cc000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.219c9cc9cc000b12"
     cluster="n3e9.219c9cc9cc000b12"
     cluster_size="184"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="kazy antifw installrex"
     md5_hashes="['07296c1bae8e49a8b93627e4de0f22d0','094fbbac0a41a853ba4695a6f90cf55c','56d6cdf4dedb191a2c7f991862a8584d']"

   strings:
      $hex_string = { 6b1e101daf69fdf3307952e90d018941906ccaaa9f398cbabbed62dd1ab92a9eefcf206d347256f8db3ebdbf3a8a8150269cd53da82fcd08974865147594c087 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
