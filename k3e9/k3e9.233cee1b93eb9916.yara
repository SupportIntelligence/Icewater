
rule k3e9_233cee1b93eb9916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.233cee1b93eb9916"
     cluster="k3e9.233cee1b93eb9916"
     cluster_size="5"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171119"
     license = "RIL-1.0 [Rick's Internet License] "
     family="backdoor qukart berbew"
     md5_hashes="['bba3c689a569a363f5893b114aacb962','bfb3f2f5cde0747ac16b01946829fab2','d4534b82521ed760ca1affa5e6c52283']"

   strings:
      $hex_string = { cd015365745365637572697479496e666f000000d401536574456e7472696573496e41636c41000018005f5f4765744d61696e417267730081015f736c656570 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
