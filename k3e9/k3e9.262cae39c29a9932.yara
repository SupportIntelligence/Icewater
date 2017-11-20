
rule k3e9_262cae39c29a9932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.262cae39c29a9932"
     cluster="k3e9.262cae39c29a9932"
     cluster_size="6"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="qukart genpack backdoor"
     md5_hashes="['b3c1de97bb8d0ae9d8b464d42ebdd7a8','c7d7de56b5f7b5b02845b1bb4b02c473','d3bbd88ddebf014359928bdf404fd4a4']"

   strings:
      $hex_string = { cd015365745365637572697479496e666f000000d401536574456e7472696573496e41636c41000018005f5f4765744d61696e417267730081015f736c656570 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
