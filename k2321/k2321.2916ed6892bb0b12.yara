
rule k2321_2916ed6892bb0b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.2916ed6892bb0b12"
     cluster="k2321.2916ed6892bb0b12"
     cluster_size="4"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="tinba zusy emotet"
     md5_hashes="['00602677aef1ac88940bde665c8c23ef','1d34699c94177a2aa170274f0dcf6277','f5b15b04d55437ef640396dac2e854e6']"

   strings:
      $hex_string = { 5d59bef4d34ff79c3efd736343c3f90b173effecb3975f7e79e3860ded7c5ec96222be2078a8e5727fad169433e8b4e4cc0c7a8887cab1c1c14477da025c8cd0 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
