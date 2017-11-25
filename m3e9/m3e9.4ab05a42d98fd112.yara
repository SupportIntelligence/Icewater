
rule m3e9_4ab05a42d98fd112
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.4ab05a42d98fd112"
     cluster="m3e9.4ab05a42d98fd112"
     cluster_size="6"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus jorik smiv"
     md5_hashes="['a4c0488a352cb37a728e6570b92a8435','a62dafacc7ab218b67e970027d5d00d4','de7cad0e67f9aff30bb9e7d1497c1ba5']"

   strings:
      $hex_string = { 8ab401fc63fbd21ccc00fdf465005b60ff080800fd88b4011a60ff4b5b0627f8fe2718ff1b66006c0c00fbfe2358ff2a4638ff08080006ac014d48ff03400808 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
