
rule o3f4_2919a19dea210912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3f4.2919a19dea210912"
     cluster="o3f4.2919a19dea210912"
     cluster_size="1614"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="androm advml backdoor"
     md5_hashes="['00092c6266129df53c253b8b58af88f0','000ea5b445826262b95eee4a6da59c64','0526eeedb16a37700523a074b30085c2']"

   strings:
      $hex_string = { 357a5756684f656b3171613046614d3070325a46684354316c584d57784252486843576b6453524749794e54425a56303477556a4e4b646d52595153745a6244 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
