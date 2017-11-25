
rule m3e9_33954ab9c9800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.33954ab9c9800b12"
     cluster="m3e9.33954ab9c9800b12"
     cluster_size="20"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="regrun ludbaruma tinba"
     md5_hashes="['07d2344264de49def7bbc1ddef75f141','07df114399f033da7f39a953b5c1a0ec','d6cb01e2fc34b8e929414e8e63708d13']"

   strings:
      $hex_string = { a4e5b17369aba1f0040ef61a289f7a8ff207b25a0d17f7cb2f2e8c8ad27e2bf9db18359543a657cda9e3f3a2d484beff4c9b3f3a353925a3aab46a96369d993d }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
