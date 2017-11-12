
rule n3e9_6b968450d6d30912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.6b968450d6d30912"
     cluster="n3e9.6b968450d6d30912"
     cluster_size="182"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="symmi kryptik reconyc"
     md5_hashes="['01a935c684f4c4299841adcbb8baf734','01f20ec394b6d0e6e222826a253ecd9a','21dc767b585f1ec9b5582b7b4e00c766']"

   strings:
      $hex_string = { 50d7a3ff8d626a5341df8def2841dbe478a3e031edc879f215e2be7d0af7feeb398ba69b4cbbe2590c08651870262c549526e5a6639528d2a7f9012484e29748 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
