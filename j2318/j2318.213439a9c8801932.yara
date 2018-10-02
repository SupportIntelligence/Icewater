
rule j2318_213439a9c8801932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j2318.213439a9c8801932"
     cluster="j2318.213439a9c8801932"
     cluster_size="154"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="redirector html script"
     md5_hashes="['01113152e3f1eeb8950839fdf5595aac30a16d8b','6d2fadecf320ee8921cf0a29653dfa37ac90b8fc','5c37e74e1637bbd29461787424ed60f6759ce0c3']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=j2318.213439a9c8801932"

   strings:
      $hex_string = { 3d227864526e6535595a516f336a6f4d49737a7156792d6e506974352d766d50315950414d6e62723765566d4122202f3e0d0a3c212d2d3c6d65746120636861 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
