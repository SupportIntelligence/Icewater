
rule k3e7_631a29bcca210912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e7.631a29bcca210912"
     cluster="k3e7.631a29bcca210912"
     cluster_size="10"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="regrun ludbaruma malicious"
     md5_hashes="['dca8b6a6088d9f2b17ffa0bbba5d45ca','dca8b6a6088d9f2b17ffa0bbba5d45ca','dca8b6a6088d9f2b17ffa0bbba5d45ca']"

   strings:
      $hex_string = { 8d34e58c30e48a2de48729e38526e28221e2801fe17d1cdf7918de7615dd7314dc7011db6d0fda6a0dd9680bd86508d86208d76007d65e06d55c05d35904d157 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
