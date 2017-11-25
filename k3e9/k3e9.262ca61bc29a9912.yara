
rule k3e9_262ca61bc29a9912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.262ca61bc29a9912"
     cluster="k3e9.262ca61bc29a9912"
     cluster_size="40"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="berbew genpack qukart"
     md5_hashes="['1b4a59cb499ee9895cc49afa17849974','377af17b3c401c6bda853248654eeff7','c6fbc3974f50fe0e7304c34c8d9016ca']"

   strings:
      $hex_string = { cd015365745365637572697479496e666f000000d401536574456e7472696573496e41636c41000018005f5f4765744d61696e417267730081015f736c656570 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
