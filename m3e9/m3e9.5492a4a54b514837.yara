
rule m3e9_5492a4a54b514837
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.5492a4a54b514837"
     cluster="m3e9.5492a4a54b514837"
     cluster_size="23"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="backdoor plite gupboot"
     md5_hashes="['12202090e45c093c3b97e26c5b7180a0','18172ba76eaee8480df10caeed5ed9e0','b4caddfaebb92ef494dae4e03c094222']"

   strings:
      $hex_string = { 0427a83d41febbb7ebf606522c05877518ce0a688d9792408c3003c8e5f7658bcdea5df332db6951b4b24f4dd60b7c24f822fbd87db1bf6715d1a3f2086e5bd2 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
