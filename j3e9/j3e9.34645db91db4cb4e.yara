
rule j3e9_34645db91db4cb4e
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3e9.34645db91db4cb4e"
     cluster="j3e9.34645db91db4cb4e"
     cluster_size="4"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut malicious attribute"
     md5_hashes="['5335b28c6b6655e4e81604d0bb542204','abb9e6bdaf1e0f56ed8af364a4d6c832','bf4bc066bebc51671556feba5c9008ae']"

   strings:
      $hex_string = { 82b940bf3cd5a6cfff491f78c2d3406fc6e08ce980c947ba93a841bc856b5527398df770e07c42bcdd8edef99dfbeb7eaa5143a1e676e3ccf2292f8481264428 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
