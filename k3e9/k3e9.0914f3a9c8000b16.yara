
rule k3e9_0914f3a9c8000b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.0914f3a9c8000b16"
     cluster="k3e9.0914f3a9c8000b16"
     cluster_size="125"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171117"
     license = "RIL-1.0 [Rick's Internet License] "
     family="backdoor razy injector"
     md5_hashes="['01e8ebd45f8652024d2a2fc6e3288c82','056f317fc1ebaec4fb7a6a6baa153e1a','5d3eac367db43ff4f55ea00e6b846696']"

   strings:
      $hex_string = { 47018a46028847028b45085e5fc9c3908d7431fc8d7c39fcf7c7030000007524c1e90283e20383f908720dfdf3a5fcff2495306840008bfff7d9ff248de06740 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
