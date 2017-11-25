
rule m3ed_104ee5a1c2000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3ed.104ee5a1c2000932"
     cluster="m3ed.104ee5a1c2000932"
     cluster_size="5"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="download malicious patched"
     md5_hashes="['110fdcc970537938f1d267ffa8e2ff62','210752419334e40cf6c46833d9104d7c','97cc5ece94d93d23888fe99f8a6a6958']"

   strings:
      $hex_string = { 2f3df43d1e3e693eb53e043f4c3fb23fc93fda3f00800000300000001630453066308830d1301a31c431cf3106337433e734e335fb351f362f39733af63b263c }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
