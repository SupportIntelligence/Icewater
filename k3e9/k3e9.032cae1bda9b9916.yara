
rule k3e9_032cae1bda9b9916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.032cae1bda9b9916"
     cluster="k3e9.032cae1bda9b9916"
     cluster_size="6"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="berbew qukart backdoor"
     md5_hashes="['3ea7f5c0feb8a132a25e0de7d6be7233','a456bf3de1ee95755511d8d2677bc1d7','ba594c7269cb95afc617093d2f04ecb8']"

   strings:
      $hex_string = { 7f932aed70da61a76dc5788278922de16a8e2cec3e9f6bab1ec230be3fca6ea23b9263af33d943a830cd43da338828d07b8435b32fe70ac7589522ef7be766f1 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
