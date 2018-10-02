
rule o26bb_47c25344ea248b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26bb.47c25344ea248b12"
     cluster="o26bb.47c25344ea248b12"
     cluster_size="191"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="gamehack malicious unsafe"
     md5_hashes="['cc06cee4e54cdf373a10002b12df41b3c7bf7801','8366c00718ee51449ad66e0789227d5fabefd57c','f1330e00fba36f0185bcef96cdf9e8ca73956588']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26bb.47c25344ea248b12"

   strings:
      $hex_string = { 44ba699380c21928431806839529860442dc11c070130d55775da73e419a7ebd98259e5330b1221f65e4e56d2cae6292f472ac904f01978dd558b85ad166f0c1 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
