
rule n3e7_0b36cec4c4add932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e7.0b36cec4c4add932"
     cluster="n3e7.0b36cec4c4add932"
     cluster_size="14"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob malicious"
     md5_hashes="['a009dbdb9e4e89d99581de6db352f8db','a61c1bf9b465727a0c43d065743c20ce','ef5ebf6bf1de0f9a7a3cd9e97ccc72dc']"

   strings:
      $hex_string = { 000102030405060708171e23272b2e313437393c3e40424446484a4c4e505153555658595b5c5e5f616263656667696a6b6c6e6f7071727375767778797a7b7c }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
