
rule k3e9_2b19f3a9c8000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.2b19f3a9c8000b32"
     cluster="k3e9.2b19f3a9c8000b32"
     cluster_size="34"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="backdoor razy injector"
     md5_hashes="['1dd2435667d7553bf35eadfc57283bf3','626df3f61286b3b86a93e8a0da689565','b86e5d15fd2e29ee0455d2afb43165d1']"

   strings:
      $hex_string = { 8847018a46028847028b45085e5fc9c3908d7431fc8d7c39fcf7c7030000007524c1e90283e20383f908720dfdf3a5fcff2495306840008bfff7d9ff248de067 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
