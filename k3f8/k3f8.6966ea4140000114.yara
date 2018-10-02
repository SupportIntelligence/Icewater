
rule k3f8_6966ea4140000114
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f8.6966ea4140000114"
     cluster="k3f8.6966ea4140000114"
     cluster_size="57"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="smforw androidos cloud"
     md5_hashes="['62eb793fde8d59d576ee12211eff4799868b51f9','fdcfc078ce9677118d80e7675dcbaab4bef3600b','3ce163f3d3ea7ace98ffa9073cbbd6f4bfc0c5dc']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k3f8.6966ea4140000114"

   strings:
      $hex_string = { 8c87e4bba4e99499e8afaf000ce6ada3e7a1aee6a0bce5bc8f20e6898be69cbae58fb7e7a08123e58685e5aeb900022d3e000470647573000367657400135b4c }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
