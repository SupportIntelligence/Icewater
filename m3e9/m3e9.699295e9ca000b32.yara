
rule m3e9_699295e9ca000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.699295e9ca000b32"
     cluster="m3e9.699295e9ca000b32"
     cluster_size="4"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="gator sfyd gain"
     md5_hashes="['24e86efc84f5ea8c6fe3dac797d66ef2','577207d31ea579223d3400dd293c2c87','db646789ec8301353aa019b8ac7266b3']"

   strings:
      $hex_string = { dc29fbfa8035d4e8d65e509939d824893d01ec6c82d0cf147725222e9686e0f17e8d26d7ab2dbd1a2389e1909b452bf408aeee65b9db30c81d8513734ca7a5b3 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
