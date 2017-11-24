
rule o3e9_35b856e0d8bb1932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.35b856e0d8bb1932"
     cluster="o3e9.35b856e0d8bb1932"
     cluster_size="6"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="cosmu mikey malicious"
     md5_hashes="['1666ee500dc7fcf1cc250e9c66a32a04','17302b4e2cef1ac4dae260254bdebb72','e1f04496adffa0af744426177c77f384']"

   strings:
      $hex_string = { ff9d55346419ab84a69e9874d7163794f0b0eca2082593e956d630f8dd407e5ed59169361787b4ba354f71e2b3f9afdc12a81d2004bb459c262c8b861bcf3a5f }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
