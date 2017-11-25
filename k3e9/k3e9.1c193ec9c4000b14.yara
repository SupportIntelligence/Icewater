
rule k3e9_1c193ec9c4000b14
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.1c193ec9c4000b14"
     cluster="k3e9.1c193ec9c4000b14"
     cluster_size="29"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="razy simbot backdoor"
     md5_hashes="['1d9ab5212fc2020f2152fa912a9ab247','2dcdbd1ccec9e4c5c6ac8fcb21f74a72','cd09d11557689a7990f334b56d04fa8c']"

   strings:
      $hex_string = { 5400720061006e0073006c006100740069006f006e00000000000904b00450414444494e47585850414444494e4750414444494e47585850414444494e475041 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
