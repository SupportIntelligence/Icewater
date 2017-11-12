
rule m3e9_611ab841cc000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.611ab841cc000b12"
     cluster="m3e9.611ab841cc000b12"
     cluster_size="20"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="allaple rahack backdoor"
     md5_hashes="['5be2ce92ea50615c495c65080f680e5e','97099e8f0ab2140552475a525a91dc9a','fad6d128a98bda85d06df53ebac33d9f']"

   strings:
      $hex_string = { e946f9c62ca36d62dd9ca71ac88dadbdc71c76cc637492e0729710d8ccc43919f004dbe788036b86b8a4804bd1596fe50c4a3f9b8a40d727bfd0696135a2569e }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
