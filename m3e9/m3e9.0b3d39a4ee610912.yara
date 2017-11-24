
rule m3e9_0b3d39a4ee610912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.0b3d39a4ee610912"
     cluster="m3e9.0b3d39a4ee610912"
     cluster_size="4"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="dinwod malob trojandropper"
     md5_hashes="['29167bc86949528bb53eee7e50ae8ed6','48bced62c0f4d6b1a51ac49bd6c9146f','d41230b8fab284a8444d3d13e407ca4b']"

   strings:
      $hex_string = { 42a19932a40459e97982fada0f4dcadb3039410b5d07c4573402a8a7a3b8316b769c7a9bdcb438ba83eb3c05b3623aec1e1f80d14369bfe1ce893ed2ae97c58b }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
