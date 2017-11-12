
rule m3f0_08e469aec6210b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f0.08e469aec6210b12"
     cluster="m3f0.08e469aec6210b12"
     cluster_size="1923"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="kazy kryptik shipup"
     md5_hashes="['002776e2a1ab1edcc3d0833f522b5364','004bd149f98fe628e450822d7fc0011f','03a9f689645230209cb033cbac4aad62']"

   strings:
      $hex_string = { 005e005348476574466f6c64657250617468570000f90047657444430095014c6f6164416363656c657261746f7273410099014c6f6164437572736f72410000 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
