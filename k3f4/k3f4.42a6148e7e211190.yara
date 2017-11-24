
rule k3f4_42a6148e7e211190
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f4.42a6148e7e211190"
     cluster="k3f4.42a6148e7e211190"
     cluster_size="103"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="krypt fraudrop malicious"
     md5_hashes="['02a72f2d785d949781b60d450eb4a68d','0a2afb05738983def5ec97ec3ca54ce0','3065ee1a2e3a7697f60c5cdc5fa3631a']"

   strings:
      $hex_string = { ec59a8e5f4abeac31c3ad666e60b3711e925100506244dac026ff9a34c74d7728da0ca168f73462cc2db6681785cd041cc6762dd54ba8bd94b146d134a3604b6 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
