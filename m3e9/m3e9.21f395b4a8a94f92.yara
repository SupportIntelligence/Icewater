
rule m3e9_21f395b4a8a94f92
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.21f395b4a8a94f92"
     cluster="m3e9.21f395b4a8a94f92"
     cluster_size="21"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ibryte bundler optimuminstaller"
     md5_hashes="['5159cae52cdb9b2a4532f462411c2cef','5f4e5261fef48fbe9f7fffd1a78e19e1','de795c8ca0d951f1aa1988f7a3639e7e']"

   strings:
      $hex_string = { faaced93ba5dc82153c2825363af120d5087111b3d5452968a2c9c3d921a089a052ec793a54891d3318202333082022f0201013081c93081b4310b3009060355 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
