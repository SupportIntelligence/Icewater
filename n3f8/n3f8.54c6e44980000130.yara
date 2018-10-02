
rule n3f8_54c6e44980000130
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f8.54c6e44980000130"
     cluster="n3f8.54c6e44980000130"
     cluster_size="15"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="androidos banker piom"
     md5_hashes="['a9aed11b7a071fe10784c3cd891abc6ba814b7b2','5eaf86d181f2e04f06f184990b65158bf38ee360','1c75c375d9f50eb75aa30ed3601ce704ac1ea93c']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n3f8.54c6e44980000130"

   strings:
      $hex_string = { 6c65616e65723b00194c73756e2f6e696f2f63682f4469726563744275666665723b00044d41494e000c4d414e554641435455524552000d4d41505045525f43 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
