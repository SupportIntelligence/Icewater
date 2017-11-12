
rule o3e9_2a4620a529495446
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.2a4620a529495446"
     cluster="o3e9.2a4620a529495446"
     cluster_size="2250"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="graftor speedingupmypc advml"
     md5_hashes="['0042c2c5a0a86ab5c5ae94623d855114','004c95c1cc903e3b308270e995291529','012abebc5b21045e4e08453d3c708cb4']"

   strings:
      $hex_string = { e81d808f9b309227d3c01db423fd7d4fe684a42da7b1f6130c2058c2c0a9e32b98368e76685851db71ca1019ca98cc99fc80c371f97523ac5830735cb81e4e70 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
