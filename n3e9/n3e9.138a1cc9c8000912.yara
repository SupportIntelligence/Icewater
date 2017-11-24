
rule n3e9_138a1cc9c8000912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.138a1cc9c8000912"
     cluster="n3e9.138a1cc9c8000912"
     cluster_size="146"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus barys malicious"
     md5_hashes="['03da7220eb34bf3a74c3caa9070fda2e','08569f0affff6ff3f4b27050275e2f39','717cb786ad8a8268a623e594216b7f44']"

   strings:
      $hex_string = { f7f3c6ffffceffffcededbbdcecfb5bdbaa5adae9cb5b29cdedfbdc6c7adc6c3adadae9ca5a69c9c9e948c8e847375736365634a4d4a424142313431292c2900 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
