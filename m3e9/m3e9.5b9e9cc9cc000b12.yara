
rule m3e9_5b9e9cc9cc000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.5b9e9cc9cc000b12"
     cluster="m3e9.5b9e9cc9cc000b12"
     cluster_size="21"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="mailru unwanted mail"
     md5_hashes="['0a9b7e0791edbbea191cd763be78f0e7','1f0fa08a2438a9cd6d4e8cdf262438ad','c76f9bb1d432ae9b8bd78e0f51e05b56']"

   strings:
      $hex_string = { e0c303cc6401859d2f7503f0c2e39f4322723d04957aefbd47d87d57fe106ba2b28d20d61c07c51bd5b0dae95faaf92d4b2ae50bdf1227383e5c374eee312e14 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
