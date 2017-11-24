
rule m3e9_0b3d39a5be630b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.0b3d39a5be630b12"
     cluster="m3e9.0b3d39a5be630b12"
     cluster_size="7"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="dinwod malob trojandropper"
     md5_hashes="['1490cc2549b7f3eb6321693be8b7495f','480ec57b4d6e138f31525a696eae53cb','f244ddead50b3f9de97a44aac8584d1d']"

   strings:
      $hex_string = { 42a19932a40459e97982fada0f4dcadb3039410b5d07c4573402a8a7a3b8316b769c7a9bdcb438ba83eb3c05b3623aec1e1f80d14369bfe1ce893ed2ae97c58b }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
