
rule k3e9_2bd5eced96264aba
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.2bd5eced96264aba"
     cluster="k3e9.2bd5eced96264aba"
     cluster_size="5"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="tinba crypt emotet"
     md5_hashes="['211889a40e63ce817ee94f38febe6f32','64f274167e84cd813f2dce042a23ae30','f532cedff7e044fd07729b5e2aab904e']"

   strings:
      $hex_string = { e18ceca271f9d2845cf49af4e45c724d62cac412e9f0dce269e3f2a4434ba665e64e491f1e1ba9c6293c6850522c5777ea3e90b7351df71491cf805588e701d6 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
