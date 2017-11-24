
rule m3e9_71c2b48dcf79ccb2
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.71c2b48dcf79ccb2"
     cluster="m3e9.71c2b48dcf79ccb2"
     cluster_size="36"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="amonetize imonetize snojan"
     md5_hashes="['1239845f9b89b8d81cd9583b3c58a627','127c36f4f172f5b95debfae0a768e624','635154de865aa3c9012d0b3f69888d14']"

   strings:
      $hex_string = { 39450c7709e81b23ffff6a22ebccc60630538d5e018bc385c97e1a8a1784d274060fbed247eb036a305a8810404985c97fe98b5514c6000085c97812803f357c }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
