
rule m2321_33956e52ea208916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.33956e52ea208916"
     cluster="m2321.33956e52ea208916"
     cluster_size="9"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="regrun ludbaruma emotet"
     md5_hashes="['0e44adbf78d8fbceaa4110d18eda539f','0ede64ef8ff4718a0a0896e2e8fff40f','df0b20b086dd62d139fa49732290fe16']"

   strings:
      $hex_string = { b4db3fbf23ecd9b6a183a7e265e817efea938bde9d519cb29b73c99e73d192bd62a621facaed58fbf247c112971e1a2d7c41f83afc32e382ae64b1f025770ab7 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
