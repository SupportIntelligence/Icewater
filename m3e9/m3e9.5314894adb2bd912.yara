
rule m3e9_5314894adb2bd912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.5314894adb2bd912"
     cluster="m3e9.5314894adb2bd912"
     cluster_size="6"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="shiz backdoor zusy"
     md5_hashes="['3f1de3ea82d5bbb7dfe7b088db3c98b7','6aefee93a292fa347915c6088d838357','f73be054e4b960a5bafb77689c67bdf6']"

   strings:
      $hex_string = { 852de8be286ca4edd5cccfab490972b4a15c21c3f0d1315497f3a8f735b9448c016dfb3764e9ad2e0d3b1762f61ddfd6f5a67434aa8c8afc590c82ac864b4c71 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
