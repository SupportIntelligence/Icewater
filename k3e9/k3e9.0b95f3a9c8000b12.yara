
rule k3e9_0b95f3a9c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.0b95f3a9c8000b12"
     cluster="k3e9.0b95f3a9c8000b12"
     cluster_size="24"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171117"
     license = "RIL-1.0 [Rick's Internet License] "
     family="backdoor tofsee injector"
     md5_hashes="['2da0891f549c6be532f26d21408ca06c','4683fc37d8b7e8f42e28cd2f75fc365d','c37a6c67d7514c44f9a3c500ae43dce8']"

   strings:
      $hex_string = { 8d49008a0688078a46018847018a46028847028b45085e5fc9c3908d7431fc8d7c39fcf7c7030000007524c1e90283e20383f908720dfdf3a5fcff2495306840 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
