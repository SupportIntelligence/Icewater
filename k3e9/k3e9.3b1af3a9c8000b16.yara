
rule k3e9_3b1af3a9c8000b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.3b1af3a9c8000b16"
     cluster="k3e9.3b1af3a9c8000b16"
     cluster_size="39"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="zusy backdoor injector"
     md5_hashes="['0c6fc1f28318dff4425dd66669213a3e','2e2243fe6ff507adb56780266d0fd695','b66a895aed9cec87ed4af30cfa22941e']"

   strings:
      $hex_string = { 8d49008a0688078a46018847018a46028847028b45085e5fc9c3908d7431fc8d7c39fcf7c7030000007524c1e90283e20383f908720dfdf3a5fcff2495306840 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
