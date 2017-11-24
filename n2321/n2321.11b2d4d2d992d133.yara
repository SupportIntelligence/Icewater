
rule n2321_11b2d4d2d992d133
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2321.11b2d4d2d992d133"
     cluster="n2321.11b2d4d2d992d133"
     cluster_size="19"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut gajgg shodi"
     md5_hashes="['00bc1b8409914f9508eaae2e0bf7b24d','128115ed0d08a8c0510635150bb5b2e0','d50366d457be770ad984462647e51d6b']"

   strings:
      $hex_string = { ce9d0df2c391958c2f19c68769095bbe61a3e278ddd55dfcbfdf444b894a0576f0b8e8624cf41b56cf86555203e5c9c1040eb92202f99bd4e454bc210fa20690 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
