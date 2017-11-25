
rule m2321_3b1d9299c2200b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.3b1d9299c2200b32"
     cluster="m2321.3b1d9299c2200b32"
     cluster_size="6"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="otwycal wapomi vjadtre"
     md5_hashes="['4e7fa20fbf08b391846978ea2fe97757','59874444a3638a955193fb13d6d86ae8','de352bab93bf34441070bc74a3b582be']"

   strings:
      $hex_string = { 8ad1422d7cb5a1cc923a31d569fd90b2abd7e065212e8f61876b8c6483019ecf1c1d74be1a2fd2e627531792c8676ae408de63aa386fe2bba91086c303256c22 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
