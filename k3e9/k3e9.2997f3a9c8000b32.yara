
rule k3e9_2997f3a9c8000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.2997f3a9c8000b32"
     cluster="k3e9.2997f3a9c8000b32"
     cluster_size="9"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="razy backdoor injector"
     md5_hashes="['4380d5bc044d7e5ce95e21ebc830ef52','85a95eb520e055015c6f2a2c5451afa7','fcfa4933391ef33a4bc1189477e405d3']"

   strings:
      $hex_string = { 47018a46028847028b45085e5fc9c3908d7431fc8d7c39fcf7c7030000007524c1e90283e20383f908720dfdf3a5fcff2495306840008bfff7d9ff248de06740 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
