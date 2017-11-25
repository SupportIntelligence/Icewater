
rule m3e9_031d3178d6c30912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.031d3178d6c30912"
     cluster="m3e9.031d3178d6c30912"
     cluster_size="4"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="fileinfector gate aovhryb"
     md5_hashes="['0cd4c0c5a1fcda266a5b16f3b605534f','19d660254149fc8e18031007e01d202a','b6f856a371d19dee9210fc2dc08983a2']"

   strings:
      $hex_string = { 3f07e3ffc7e4cdb54d5c26f9ac2d6c06c61364e554090fb0800e5a60be705f58ec0b4cb43738f505ce7d814b6fa06d0d8d6b2f63ade1c9b8352885d6a69dd101 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
