
rule m3e9_2b1d6b729ec30b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.2b1d6b729ec30b12"
     cluster="m3e9.2b1d6b729ec30b12"
     cluster_size="20"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus symmi pronny"
     md5_hashes="['0d6ba97afb8106629a898c5c6355d597','20fd9c2b2f573f33c5dd2b875181b25d','eae179dcfc4500841ba52101af9ef665']"

   strings:
      $hex_string = { 1b4948525c572c4e584b494a5b898a8a949697969597d6eefaf2fafdfdfcf8f4a7000000f4fefe03141b1716161617214c5257606b6e83a4c5bcb0b0babdc1c1 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
