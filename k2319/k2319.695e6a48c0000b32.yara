
rule k2319_695e6a48c0000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.695e6a48c0000b32"
     cluster="k2319.695e6a48c0000b32"
     cluster_size="30"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="multiplug script asmalwsc"
     md5_hashes="['f89795280dd98f321568e475d11f8e60aaf99b7b','6f0d1658c5fe459217900b3460e7be8591a1bef0','7c2ae891ebe9aef8521bce658505c06c007da5fc']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.695e6a48c0000b32"

   strings:
      $hex_string = { 6c73657b613d746869735b28642b5136295d3b7d666f722876617220753d755b284b2b682b76312b4c312b622b70312b68295d282f5b5e412d5a612d7a302d39 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
