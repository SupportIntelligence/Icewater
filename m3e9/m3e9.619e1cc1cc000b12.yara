
rule m3e9_619e1cc1cc000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.619e1cc1cc000b12"
     cluster="m3e9.619e1cc1cc000b12"
     cluster_size="262"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="allaple rahack backdoor"
     md5_hashes="['04ac13a37b9e8bc18d452e5deb202d20','068b581b0a87b972c45aecfdd1b9bbbb','2e4953f9dc964f4a2202a0c0427dbafd']"

   strings:
      $hex_string = { 073d58e5ad3b88c1e70c8b72fe451a41a413a78a1ec8bed4ffc97b1dc250f96bb0da4cbd623c9e9247a6cbbb5ab41f9adc5e3b8ef7e20e208fe10b6a5267dd00 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
