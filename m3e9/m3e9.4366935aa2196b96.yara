
rule m3e9_4366935aa2196b96
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.4366935aa2196b96"
     cluster="m3e9.4366935aa2196b96"
     cluster_size="9"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="nsis adload clickdownload"
     md5_hashes="['31e372cd705ea3abc630507b41f443c7','40eb9db4aff397e0b97547e61a701c13','ec2e7e0b35c43f7d054c6de9c2aa9805']"

   strings:
      $hex_string = { a0e43f75cac12da33a391321d38da6dd933e0dc7c0746864b1c5d452cb1f148172f2444c7fb985f2057840cd8e914602fa6fac112320bdc91d70808c7a5ab2bc }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
