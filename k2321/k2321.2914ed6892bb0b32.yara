
rule k2321_2914ed6892bb0b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.2914ed6892bb0b32"
     cluster="k2321.2914ed6892bb0b32"
     cluster_size="8"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171117"
     license = "RIL-1.0 [Rick's Internet License] "
     family="zusy emotet tinba"
     md5_hashes="['23c96fff12aad6886fe0ac395275ee5d','29d7c4f27cacd33e0ffd4c38a81c42e6','deb3dd918b9666a50355cbb755e7d73b']"

   strings:
      $hex_string = { 5d59bef4d34ff79c3efd736343c3f90b173effecb3975f7e79e3860ded7c5ec96222be2078a8e5727fad169433e8b4e4cc0c7a8887cab1c1c14477da025c8cd0 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
