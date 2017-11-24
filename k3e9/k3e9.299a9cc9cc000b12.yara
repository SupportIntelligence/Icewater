
rule k3e9_299a9cc9cc000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.299a9cc9cc000b12"
     cluster="k3e9.299a9cc9cc000b12"
     cluster_size="24"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="rincux ddos qqhelper"
     md5_hashes="['2a0a19ba842b202dfc2865cb74c2d6dc','31064028d51bbd3d31a39a15b796b704','c2df1e580bf3dea6df5e7f241c935b4a']"

   strings:
      $hex_string = { 8e5a785b24761eeb68d33d2c741b1c1fa18231220eea4c6e61ccdf73f84d7986c116bf5eb6e54630e09e66fc2e67920df92ae18b6043ee2f23bcbbde281bf407 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
