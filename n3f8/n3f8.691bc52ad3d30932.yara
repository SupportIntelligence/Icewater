
rule n3f8_691bc52ad3d30932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f8.691bc52ad3d30932"
     cluster="n3f8.691bc52ad3d30932"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="droidkungfu androidos kungfu"
     md5_hashes="['da16a6ffc7fd3cf7ee0526c683520c0696eb63f3','db5ba274a859b61d5748000b20da8c2263c3b596','040bdeb9f168637c36e191c099658956182e7732']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n3f8.691bc52ad3d30932"

   strings:
      $hex_string = { bdefbc8ce8afb7e59ca8e9809ae79fa5e4b8ade98089e68ba922e585b3e997ad55534220e5ad98e582a822000353444b001253444b4765744170704e616d6545 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
