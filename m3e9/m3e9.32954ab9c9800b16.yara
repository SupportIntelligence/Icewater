
rule m3e9_32954ab9c9800b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.32954ab9c9800b16"
     cluster="m3e9.32954ab9c9800b16"
     cluster_size="15"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="regrun ludbaruma tinba"
     md5_hashes="['0952f5ec4d22ceda8a3b0d7ad0f3962b','09b57f9dc3371117cf163b289381b6ac','ee3ee8b53b81a7b1b36d93f903f8ab39']"

   strings:
      $hex_string = { a7bba1a62e1871fab53d2d0a3ce251caf3421e0f644ab9d4e32f0c47d4724524a436d1b628f586238a56b1dfad1cdb9b22d3146cb7f7919ac6e9f9dab665cb1a }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
