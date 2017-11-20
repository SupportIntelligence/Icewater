
rule k3e9_2b1af3a9c8000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.2b1af3a9c8000b32"
     cluster="k3e9.2b1af3a9c8000b32"
     cluster_size="337"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="backdoor razy injector"
     md5_hashes="['0085b5588546381a04f9497b0c0e1a74','01bcec84a82e8f22c1ca5fa438dcd013','213c4fde02ae4156c1f19f2e322335ff']"

   strings:
      $hex_string = { 8d49008a0688078a46018847018a46028847028b45085e5fc9c3908d7431fc8d7c39fcf7c7030000007524c1e90283e20383f908720dfdf3a5fcff2495306840 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
