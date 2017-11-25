
rule k3e9_2998f3a9c8000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.2998f3a9c8000b32"
     cluster="k3e9.2998f3a9c8000b32"
     cluster_size="41"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="razy injector backdoor"
     md5_hashes="['02691749dddc4719272f567b2ce8ef34','0ae2784d0f48a6f3f15290cf0d819e58','a575dc690dcf2966c90a7417f08d6688']"

   strings:
      $hex_string = { 8d49008a0688078a46018847018a46028847028b45085e5fc9c3908d7431fc8d7c39fcf7c7030000007524c1e90283e20383f908720dfdf3a5fcff2495306840 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
