
rule n3e9_11b2d4d2d992d133
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.11b2d4d2d992d133"
     cluster="n3e9.11b2d4d2d992d133"
     cluster_size="15"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut gajgg shodi"
     md5_hashes="['128115ed0d08a8c0510635150bb5b2e0','183e9cb743749b640fd09af470fb8d4c','f9cbf402e6bf300eb0bc07f7ef8a1996']"

   strings:
      $hex_string = { ce9d0df2c391958c2f19c68769095bbe61a3e278ddd55dfcbfdf444b894a0576f0b8e8624cf41b56cf86555203e5c9c1040eb92202f99bd4e454bc210fa20690 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
