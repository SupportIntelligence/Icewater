
rule n2726_3a95f841c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2726.3a95f841c4000b12"
     cluster="n2726.3a95f841c4000b12"
     cluster_size="62"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="barys malicious stantinko"
     md5_hashes="['819f5c8b7e8bd9890ec44a3891d7ab8f1b54bc06','cfce9b021772982f1de9024b84109da08633a60f','15750982300e0310f63659aeff2c4de6861b98e6']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n2726.3a95f841c4000b12"

   strings:
      $hex_string = { c8e83225dcffb898d05910e9e928dcffccccccccccc745fca1260000c363b12f820639903774ca05b2908e3eeb228b480483c1248b01ff500c8d7e08eb1233db }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
