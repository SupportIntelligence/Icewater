
rule m3e9_32954cc9cc000b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.32954cc9cc000b16"
     cluster="m3e9.32954cc9cc000b16"
     cluster_size="6"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="regrun ludbaruma emotet"
     md5_hashes="['4110f3f690df81d083a6433022208c51','446331a1486b60848104d8ae3bc598a4','daeac8ff7832a0eb4dafee6a09f2d8c0']"

   strings:
      $hex_string = { a7bba1a62e1871fab53d2d0a3ce251caf3421e0f644ab9d4e32f0c47d4724524a436d1b628f586238a56b1dfad1cdb9b22d3146cb7f7919ac6e9f9dab665cb1a }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
