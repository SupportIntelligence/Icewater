
rule m3e9_6319b8c1cc000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.6319b8c1cc000b12"
     cluster="m3e9.6319b8c1cc000b12"
     cluster_size="137"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="allaple rahack backdoor"
     md5_hashes="['0084ba5863b277f362f2dc32297e9648','06bef2827dddfce462480077abe97ef3','607ce76d09056ad3421881d7ab7f0b38']"

   strings:
      $hex_string = { 0cfa4d6a8edacf4a10bb512b929bd30b147c55ec965cd7cc183d59ad9a1ddb8d1cfe5d6e9ededf4e20bf612fa29fe30f248065f0a660e7d0284169b1aa21eb91 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
