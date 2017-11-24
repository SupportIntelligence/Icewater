
rule k2321_292d1962d9eb1932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.292d1962d9eb1932"
     cluster="k2321.292d1962d9eb1932"
     cluster_size="4"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus razy vbkrypt"
     md5_hashes="['30d57a9067cfc1869e7bebe8c6ec3e62','32b46ebd6e85835fa07d725f83020d4e','e5c2d183b3d6c3c7e02e28770d44bfa9']"

   strings:
      $hex_string = { 5e301986b5ab227c40a519c0344fa9f538085ce29abc21854a4bf2cef38cd88eed6057a627c4b666825d9996b7976bd98deb6a72dd59472f15179c432cfac8cb }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
