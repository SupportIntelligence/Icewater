
rule k3e9_3316f3a9c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.3316f3a9c8000b12"
     cluster="k3e9.3316f3a9c8000b12"
     cluster_size="13"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="razy backdoor injector"
     md5_hashes="['090ee7c294594e7f2eb2011871594959','189dbbeaf7df1428c6848f95ffa36827','d48ea1bc23a01b721144b5bc8b2aa497']"

   strings:
      $hex_string = { 8d49008a0688078a46018847018a46028847028b45085e5fc9c3908d7431fc8d7c39fcf7c7030000007524c1e90283e20383f908720dfdf3a5fcff2495306840 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
