
rule n3e9_1bc2948dee650b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.1bc2948dee650b16"
     cluster="n3e9.1bc2948dee650b16"
     cluster_size="3"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="dealply malicious attribute"
     md5_hashes="['6b7542f34884bb02d577825a8e22d8e6','bf39cdd2e1df931fce2fecde38ddca38','fb42ce20cc7ba7f0432619ecfd69c402']"

   strings:
      $hex_string = { 000b00590065007300200074006f002000260041006c006c00040042006b005300700003005400610062000300450073006300050045006e0074006500720005 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
