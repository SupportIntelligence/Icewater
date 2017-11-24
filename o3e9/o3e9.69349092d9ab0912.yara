
rule o3e9_69349092d9ab0912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.69349092d9ab0912"
     cluster="o3e9.69349092d9ab0912"
     cluster_size="171"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="graftor zusy backdoor"
     md5_hashes="['007e56bce47938c147b802d4604b7b9b','01b55863c70af7ffc66cf8405e144339','1a0da4b1637cf1d309bc095f45f53188']"

   strings:
      $hex_string = { c7b197e3ab3fd60ded23246f5ebe7aba6118d11270adf663fb46173e018caef9fe7e60a6764fb519b61ef18b04db16e808072f56344ea598c9f4f3627ca8281b }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
