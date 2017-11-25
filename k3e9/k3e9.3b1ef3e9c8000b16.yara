
rule k3e9_3b1ef3e9c8000b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.3b1ef3e9c8000b16"
     cluster="k3e9.3b1ef3e9c8000b16"
     cluster_size="23"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="razy backdoor simbot"
     md5_hashes="['1745fa1f796d40fca361f8611ba39df0','2b6c00c16b9a4da8fb25ca5cb9639f33','db7e1fbfac0407ea90b5b2539c5a6b92']"

   strings:
      $hex_string = { 8d49008a0688078a46018847018a46028847028b45085e5fc9c3908d7431fc8d7c39fcf7c7030000007524c1e90283e20383f908720dfdf3a5fcff2495306840 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
