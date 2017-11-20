
rule m3e9_5492a4a54b51a827
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.5492a4a54b51a827"
     cluster="m3e9.5492a4a54b51a827"
     cluster_size="8"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="backdoor plite gupboot"
     md5_hashes="['4aeebe32664af67fe0f6fc973c1f97c4','6c10ff15be29d91b5e239caf7375fd3c','e87a8a774e1335a4836b21e744b61deb']"

   strings:
      $hex_string = { 0427a83d41febbb7ebf606522c05877518ce0a688d9792408c3003c8e5f7658bcdea5df332db6951b4b24f4dd60b7c24f822fbd87db1bf6715d1a3f2086e5bd2 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
