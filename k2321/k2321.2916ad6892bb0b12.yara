
rule k2321_2916ad6892bb0b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.2916ad6892bb0b12"
     cluster="k2321.2916ad6892bb0b12"
     cluster_size="5"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="tinba emotet zusy"
     md5_hashes="['74e2c5659e72a5a8ff4d44a74550efd8','9e2d9f3502f2af3501550eb26a8cff7a','ff61b5eda9962eb3c83afed3ffac2acf']"

   strings:
      $hex_string = { 5d59bef4d34ff79c3efd736343c3f90b173effecb3975f7e79e3860ded7c5ec96222be2078a8e5727fad169433e8b4e4cc0c7a8887cab1c1c14477da025c8cd0 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
