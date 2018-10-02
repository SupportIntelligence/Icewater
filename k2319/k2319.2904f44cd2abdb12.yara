
rule k2319_2904f44cd2abdb12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.2904f44cd2abdb12"
     cluster="k2319.2904f44cd2abdb12"
     cluster_size="17"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script plugin"
     md5_hashes="['d73331c3d0e349231812df159e412a22b6601142','f3fdefa6776df2ab797fb592a0114d5a4d5616c7','5c1a939f8c16e8e979a9254ee57088a07c931f22']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.2904f44cd2abdb12"

   strings:
      $hex_string = { 31322e31394532293a2834382c3078323339292929627265616b7d3b7661722053385a3d7b27503167273a2773272c275234273a66756e6374696f6e28772c74 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
