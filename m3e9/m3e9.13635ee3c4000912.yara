
rule m3e9_13635ee3c4000912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.13635ee3c4000912"
     cluster="m3e9.13635ee3c4000912"
     cluster_size="168"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="installcore unwanted bscope"
     md5_hashes="['01ed073386c1ade858730dc4dcefb96a','02b97cc3adfc92a4cd62101cf2b57fb8','2315150d50db7569ea46e894f87f7701']"

   strings:
      $hex_string = { 5d6b6520abe95cd3f56eb5ade304dd23094061ae2ad239cfbcec237f9218e2a1a3c90bfb98d63b0ea691cc7155ee877e7781eb421d70dbb622f6a8600d438841 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
