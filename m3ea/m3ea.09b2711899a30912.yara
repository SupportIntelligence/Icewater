
rule m3ea_09b2711899a30912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3ea.09b2711899a30912"
     cluster="m3ea.09b2711899a30912"
     cluster_size="12"
     filetype = "Java archive data (JAR) (gzip compressed data"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="hiddad androidos generickd"
     md5_hashes="['196ce80da31cc31bbd5d314b98a669fe','3c3009f6606fe1c46d2092c8fc67daa4','f5efe45c042c7fcd2245bed2e8a0e55d']"

   strings:
      $hex_string = { 82c9c39d124e5b69402f34c7fda0fa301fa8ca87883bcb590142c889293927e90dc5d4be7bd65a81cd22ea8c63fc3ea3ee5713d1c6fe4f6cd98aff2673ce4b95 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
