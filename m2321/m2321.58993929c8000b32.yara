
rule m2321_58993929c8000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.58993929c8000b32"
     cluster="m2321.58993929c8000b32"
     cluster_size="82"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['07f62f47726897e9ce42b14347e00d90','0b2750d5830236de9cb250ce0ffc4b17','26a09e9c88c7f3bf165fda3a3988e024']"

   strings:
      $hex_string = { 8c59e84120c2a15a08836c7a3617a80e9613484a712ef2d5f529a05b87553a2fe2ebc85265b9fab890c49503ed86bbd1bb3c1e1dbf78773cdc2bd6a99b0480f8 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
