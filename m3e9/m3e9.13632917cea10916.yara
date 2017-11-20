
rule m3e9_13632917cea10916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.13632917cea10916"
     cluster="m3e9.13632917cea10916"
     cluster_size="61"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="installcore malicious dealply"
     md5_hashes="['05cff5f9584cbe5f1793ac42858d46fe','0a8ef18c2d7cabef2db100b706d0024e','552615617e38dff392c1fa32a10dc764']"

   strings:
      $hex_string = { e429371a03f8ee38c92b0d5b67234b8155d497cc7ff7b6fef2bc339398d8a2c6c7fdff1d0e8299715a0b00b2b4844eaa72f5130fdd54c3c0f3525da874944acb }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
