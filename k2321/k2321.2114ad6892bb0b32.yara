
rule k2321_2114ad6892bb0b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.2114ad6892bb0b32"
     cluster="k2321.2114ad6892bb0b32"
     cluster_size="12"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="tinba zusy vbkrypt"
     md5_hashes="['0e0f90c1bf97ebc8837afd83f343367e','2770fda2278bed4d4f7ecddd866087bc','fac3db18993f29f8f2e94993147c4059']"

   strings:
      $hex_string = { 5d59bef4d34ff79c3efd736343c3f90b173effecb3975f7e79e3860ded7c5ec96222be2078a8e5727fad169433e8b4e4cc0c7a8887cab1c1c14477da025c8cd0 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
