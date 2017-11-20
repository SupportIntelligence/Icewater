
rule k3e9_6a9297999ea10912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.6a9297999ea10912"
     cluster="k3e9.6a9297999ea10912"
     cluster_size="23"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="adload nsis trojandownloader"
     md5_hashes="['1bcc3de63f156da5c80c24117806430a','28e7d2323bfac673af7c6bdc1c6fb502','d48f8f89e0ef23f9cfe0a32ed55e60eb']"

   strings:
      $hex_string = { c07c2b568d7041c1e6055703f18d78018b0685c07410837efcff750a50ff150430001083260083ee204f75e45f5ec3518b4424085355568b981408000057895c }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
