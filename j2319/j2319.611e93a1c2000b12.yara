
rule j2319_611e93a1c2000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j2319.611e93a1c2000b12"
     cluster="j2319.611e93a1c2000b12"
     cluster_size="7"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="multiplug diplugem megasearch"
     md5_hashes="['176ae1a47454e57ded1d36d2c8f36afb7ad13af8','a294fa74e47714cdbfe072217f2d0f57816a13da','e7edf0f21b57f31e3c6a203022cc4cb41c9c05df']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=j2319.611e93a1c2000b12"

   strings:
      $hex_string = { 3a22616263647778797a737475767271706f6e6d696a6b6c65666768414243445758595a535455564d4e4f505152494a4b4c4546474839383736353433323130 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
