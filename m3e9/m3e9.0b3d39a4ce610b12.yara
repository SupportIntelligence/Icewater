
rule m3e9_0b3d39a4ce610b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.0b3d39a4ce610b12"
     cluster="m3e9.0b3d39a4ce610b12"
     cluster_size="66"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="dinwod trojandropper avyl"
     md5_hashes="['03cb9f7f567294ec36996a0519611102','0522e4c32f84d5ba5637fb509877b3b3','498ca3e1dcec7b95625fba00c0565055']"

   strings:
      $hex_string = { 42a19932a40459e97982fada0f4dcadb3039410b5d07c4573402a8a7a3b8316b769c7a9bdcb438ba83eb3c05b3623aec1e1f80d14369bfe1ce893ed2ae97c58b }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
