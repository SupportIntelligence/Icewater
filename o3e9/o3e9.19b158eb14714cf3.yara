
rule o3e9_19b158eb14714cf3
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.19b158eb14714cf3"
     cluster="o3e9.19b158eb14714cf3"
     cluster_size="740"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="installmonster installmonstr malicious"
     md5_hashes="['001ce911265eb93c8443f75333ccf288','002e9f550b2dac19923ec70d2bd17c09','063a7e067bfaa8d0b407b59d66e3c5a2']"

   strings:
      $hex_string = { 33969c37568ade24c696ef8d9689b41e8bdbf86468c66ec06af58e1dd2ed00343a62e85490136a2c5174bddf69e45336ab779899fa9c52bfdd37940ad3d302ca }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
