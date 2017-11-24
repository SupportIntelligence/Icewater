
rule m2321_0b3d39a4ce610b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.0b3d39a4ce610b12"
     cluster="m2321.0b3d39a4ce610b12"
     cluster_size="316"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="dinwod malob trojandropper"
     md5_hashes="['000738b08b9578a67db880b0c04398cf','00ca568642f02b5528354d2b3d03b4e5','0875ac531e7fa267fa953a625b916f5f']"

   strings:
      $hex_string = { 42a19932a40459e97982fada0f4dcadb3039410b5d07c4573402a8a7a3b8316b769c7a9bdcb438ba83eb3c05b3623aec1e1f80d14369bfe1ce893ed2ae97c58b }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
