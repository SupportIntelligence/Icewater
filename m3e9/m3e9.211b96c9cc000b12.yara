
rule m3e9_211b96c9cc000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.211b96c9cc000b12"
     cluster="m3e9.211b96c9cc000b12"
     cluster_size="33"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vbna deepscan cambot"
     md5_hashes="['0b60afad0838a87e55acaf641a87bead','0f9e9bbfcb2a71aa0ac530fefb163ab0','7da4b36d58bf980b1a05b27af4846b69']"

   strings:
      $hex_string = { d163b446a6ef7515311a3b07915a68fa2e7f6f08f6ee2df4a910cfdc180dab8ad5336480a4a44036ed65be93cd4e0f60d27d2ad41ef81cf9b3962654588f94c9 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
