
rule o3e9_09124212d7a30912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.09124212d7a30912"
     cluster="o3e9.09124212d7a30912"
     cluster_size="63"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="graftor noobyprotect fuery"
     md5_hashes="['008b486ce67ea345af8de6f648e028f7','038e1b934659ebbea511968e55cc4146','3d787e1deaad59dc3fa99f5aaf7e98c9']"

   strings:
      $hex_string = { 8983b79bc7d9e4598d9f5708e2f67a6f77138bd8bed72dce3691cd994c864625fc2ea0e560b2af5093615d03971ee995dfb50eb1118e2835e7adc0d35b3a32a9 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
