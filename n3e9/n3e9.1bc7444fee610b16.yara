
rule n3e9_1bc7444fee610b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.1bc7444fee610b16"
     cluster="n3e9.1bc7444fee610b16"
     cluster_size="5"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="dealply malicious ageneric"
     md5_hashes="['1e0d346f2343e8aeb4c01ed90065a762','3dc3bfa4f4d89d38a3319056b9ec292a','c0b4adb081f8a59b4db8a3a8ff33225d']"

   strings:
      $hex_string = { 000b00590065007300200074006f002000260041006c006c00040042006b005300700003005400610062000300450073006300050045006e0074006500720005 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
