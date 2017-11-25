
rule n3e9_29146a49c0000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.29146a49c0000b32"
     cluster="n3e9.29146a49c0000b32"
     cluster_size="29"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="dealply bundler malicious"
     md5_hashes="['07d0362881eb76686d5d1f6bd08ec940','081a6c21ab9f20b5423f071de489b02c','9fa6a9a6aa21f2180b35aaa556564d26']"

   strings:
      $hex_string = { 004578697450726f63657373000000526567436c6f73654b6579000000496d6167654c6973745f41646400000053617665444300004973457175616c47554944 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
