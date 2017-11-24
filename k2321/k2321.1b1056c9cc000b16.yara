
rule k2321_1b1056c9cc000b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.1b1056c9cc000b16"
     cluster="k2321.1b1056c9cc000b16"
     cluster_size="5"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="small generickd upatre"
     md5_hashes="['704fc75296a8c3dd1850160b5bbf9341','7d9c66695b4cf3f1df76f2688b22d329','f4bb8440b5ba7cc4c70857e6b1214085']"

   strings:
      $hex_string = { 75fcccad26f38afb44b3172e1d557bc79c1132014fdd342fbe65b5cbb42afb566ed7395e7f9bcdd499edea1f3025677c885a40d67e9fd931e74c8000ab853707 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
