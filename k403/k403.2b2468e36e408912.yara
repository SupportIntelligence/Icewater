
rule k403_2b2468e36e408912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k403.2b2468e36e408912"
     cluster="k403.2b2468e36e408912"
     cluster_size="1873"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="browsefox netfilter yotoon"
     md5_hashes="['0066b5464c84b425d4ccbd7e9e3f2a19','00d05cbd7ace6d135451da4c3d77088f','031c92b0c44e95223650e3a641910432']"

   strings:
      $hex_string = { 8c639d17a308a5abb0fbcd6a62824cd521da1bd9f1e3843b8a2a4f855b90014fc9a776107f27037cbeae7e7dc1ddf905bc1b489c69e7c0a43c3c41003edf96e5 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
