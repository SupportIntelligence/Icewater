
rule m2321_0b3a59cecf366916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.0b3a59cecf366916"
     cluster="m2321.0b3a59cecf366916"
     cluster_size="4"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="dinwod kazy eydrop"
     md5_hashes="['15661baa5a2850c6c8fd4eaec229ecc9','3781ee1c51eae3c6a9a99cb7346c91ae','806284a3832224d45818da5c45e4e94f']"

   strings:
      $hex_string = { 21f01bdb14b744e835d74a631caf5ec3f1eae739ac5df650d6d5622e4d30f26fb39a03238375f4adb442a246c048825a3ea5a7e447a85c5606fac5e08a8054d9 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
