
rule k2319_1a109699c2200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.1a109699c2200b12"
     cluster="k2319.1a109699c2200b12"
     cluster_size="102"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['788b91038bcdeec7d14c5b2fb738a771061db596','9d186e5fa732ae527d785c17218b8de4077afc2c','90dde97f9a644b91caf5e6efbb0d055fd4f05899']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.1a109699c2200b12"

   strings:
      $hex_string = { 312e3032364533292929627265616b7d3b7661722075304a35353d7b2744384d273a2268222c2746346c273a2264222c274a3835273a66756e6374696f6e2877 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
