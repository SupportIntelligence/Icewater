
rule o3e9_59b33ec9c4000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.59b33ec9c4000932"
     cluster="o3e9.59b33ec9c4000932"
     cluster_size="273"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virlock nabucur ransom"
     md5_hashes="['03d1dada172a05f7a01c4dee7b13c2bf','0409bdd8531f6a7b854b1008caafc4f2','2a511f25b3a53483c14f8b1fd05dd0eb']"

   strings:
      $hex_string = { 010001002020000002002000a8100000010050414444494e47585850414444494e4750414444494e47585850414444494e4750414444494e4758585041444449 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
