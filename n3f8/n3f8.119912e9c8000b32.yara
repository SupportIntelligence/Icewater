
rule n3f8_119912e9c8000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f8.119912e9c8000b32"
     cluster="n3f8.119912e9c8000b32"
     cluster_size="9"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="bankbot adlibrary androidos"
     md5_hashes="['6c7fd557003cf1f4cc9b84637c43583712a5f135','0e4b1b74e82b7f3e625eea741dfce77512166511','c689a1c8361d4837c21368628a4f912aba732602']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n3f8.119912e9c8000b32"

   strings:
      $hex_string = { 245468656d653b001f4c616e64726f69642f636f6e74656e742f7265732f5265736f75726365733b00194c616e64726f69642f67726170686963732f4269746d }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
