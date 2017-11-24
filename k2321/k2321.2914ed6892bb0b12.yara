
rule k2321_2914ed6892bb0b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.2914ed6892bb0b12"
     cluster="k2321.2914ed6892bb0b12"
     cluster_size="17"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="tinba emotet zusy"
     md5_hashes="['0876ea51ec7c29416645587dcc85c242','0c65dcd96f19214ce4a9a7af43bf4ca5','fe82fc439184a3379c11a237edaa34be']"

   strings:
      $hex_string = { 5d59bef4d34ff79c3efd736343c3f90b173effecb3975f7e79e3860ded7c5ec96222be2078a8e5727fad169433e8b4e4cc0c7a8887cab1c1c14477da025c8cd0 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
