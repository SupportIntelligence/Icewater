
rule m3e9_6b2f05945ebbab16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.6b2f05945ebbab16"
     cluster="m3e9.6b2f05945ebbab16"
     cluster_size="55"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171119"
     license = "RIL-1.0 [Rick's Internet License] "
     family="otwycal wapomi vjadtre"
     md5_hashes="['178957312b466f6f740df83022454f32','1ba8f4b785ef00aee3e54cb428215a8b','ac644743fc6afe1e0fa5e74939931b2e']"

   strings:
      $hex_string = { 443a5b59460e7b54c5186db9a2749dee2fcee572d0192d78e9c45de7e2c99ec0f5a1f16886f8b18bc25332f7c827bf0a405f02cd91339631cf51fc08be9c2af6 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
