
rule n3e9_16b6ccc184000954
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.16b6ccc184000954"
     cluster="n3e9.16b6ccc184000954"
     cluster_size="243"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="allaple rahack malicious"
     md5_hashes="['039efb8016009c0a7ff0cac777686cd6','077191269839dd639a0db9e0bee87d2f','20259419d1331c526b4d54a22c95608e']"

   strings:
      $hex_string = { c2a1e2d526fbdcd0a83236d35284cefae54e06f2fd27daff1063516fd45f0e711ff4b57bbcdd4b7e6383be29a7d888348170869877c1249d8d0a6a900b5c1895 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
