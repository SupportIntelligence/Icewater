
rule n3e9_1bc49cd6dae30932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.1bc49cd6dae30932"
     cluster="n3e9.1bc49cd6dae30932"
     cluster_size="3"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="dealply bundler malicious"
     md5_hashes="['4206f3d7d5911707e86158cc472ac95e','78c7d053ec8b8e63933a2665e20d96f5','fc04d9d39bf07d4e047fe36760580200']"

   strings:
      $hex_string = { 000b00590065007300200074006f002000260041006c006c00040042006b005300700003005400610062000300450073006300050045006e0074006500720005 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
