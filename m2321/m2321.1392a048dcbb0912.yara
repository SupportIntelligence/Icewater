
rule m2321_1392a048dcbb0912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.1392a048dcbb0912"
     cluster="m2321.1392a048dcbb0912"
     cluster_size="4"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="backdoor elzob zusy"
     md5_hashes="['aedc552cc1aad657e8ff7b4d8015e91c','e078e5bb0e0468f697226a9c76acc4a0','f1e9f811d3d7f34a28fb409c7e5eeae8']"

   strings:
      $hex_string = { 258b9967beb1492e9e656baa94e72fbc8c21c5f3bdcab25197cb6c31af4bfdedebd0c3f880199bc4c6adba85306690878e00898ddb4bc829f056fa082d266fc1 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
