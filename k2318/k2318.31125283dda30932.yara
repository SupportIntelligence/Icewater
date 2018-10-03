
rule k2318_31125283dda30932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.31125283dda30932"
     cluster="k2318.31125283dda30932"
     cluster_size="27"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="redirector iframe html"
     md5_hashes="['b3b3efed09f8a474d46441b2c311586204d04116','a3da8afccbf6a048966d0ff35da6ea2759305fe0','d8b97ff2fc24e2e6db94838d52584a89fe0eafe2']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.31125283dda30932"

   strings:
      $hex_string = { 2e7375626d697428293b222073697a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c454354 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
