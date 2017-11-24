
rule k3e9_29259123d9eb1912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.29259123d9eb1912"
     cluster="k3e9.29259123d9eb1912"
     cluster_size="4"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus symmi vbkrypt"
     md5_hashes="['2f9f7bfba9a4bafac5ff7b9f4d26970d','9277d05b23309e28081f7fa7280efa78','cfabb2b9d5705aa6c43667af42862467']"

   strings:
      $hex_string = { a6c4d95dae441f1d0305b360409dafb23ff19333aba00b361b9d0fba0a79566c098f5a396bffd1b84e4ac93a2e7a8e3568c5c845a2e34bdcccf6df4c65ecc3d8 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
