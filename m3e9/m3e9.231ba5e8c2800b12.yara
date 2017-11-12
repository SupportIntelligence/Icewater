
rule m3e9_231ba5e8c2800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.231ba5e8c2800b12"
     cluster="m3e9.231ba5e8c2800b12"
     cluster_size="13"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob malicious"
     md5_hashes="['19176ccc45b163341fc39b91ea013e17','2682ab5f8339c47daa373d7b79f053ef','f84d2b814629f18af1b95e45c899a0ed']"

   strings:
      $hex_string = { d9c1e902756c8807474b75fa5b5e8b4424085fc3891783c7044974afbafffefe7e8b0603d083f0ff33c28b1683c604a90001018174de84d2742c84f6741ef7c2 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
