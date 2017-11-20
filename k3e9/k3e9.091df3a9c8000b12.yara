
rule k3e9_091df3a9c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.091df3a9c8000b12"
     cluster="k3e9.091df3a9c8000b12"
     cluster_size="104"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171117"
     license = "RIL-1.0 [Rick's Internet License] "
     family="backdoor tofsee injector"
     md5_hashes="['099b201d60a93d30dd382d2d29b0a1e9','0c71d3181918dcd1f5b5ed36c62df5d5','7d94e88f15fdd83b9c15dac608d619b2']"

   strings:
      $hex_string = { 8d49008a0688078a46018847018a46028847028b45085e5fc9c3908d7431fc8d7c39fcf7c7030000007524c1e90283e20383f908720dfdf3a5fcff2495306840 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
