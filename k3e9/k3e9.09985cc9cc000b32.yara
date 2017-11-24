
rule k3e9_09985cc9cc000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.09985cc9cc000b32"
     cluster="k3e9.09985cc9cc000b32"
     cluster_size="14"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="rincux ddos stormattack"
     md5_hashes="['0bc06f79316e198090f9715901d5a703','11cb11d974a037b3f374372400de55ab','f446517bc0df38bb3251f8b7eae1e342']"

   strings:
      $hex_string = { 800e501a8fbe85ab3c6d7059da5ec188010cb7b5b0e3e23b2d039ef6ec0b92d4f2756f0ce2361fba23f170d790ca221e3edb261debb800e47b4e7cfffc9f9781 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
