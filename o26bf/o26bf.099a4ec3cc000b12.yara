
rule o26bf_099a4ec3cc000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26bf.099a4ec3cc000b12"
     cluster="o26bf.099a4ec3cc000b12"
     cluster_size="6"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="temonde malicious adload"
     md5_hashes="['546d9edf538a456d14e7cc80cca27c053b383928','0b1de6a0f44ef7b993e2518d72c043f6dc1360f9','3f097d3bc414bb60d11f17f6dc321e449ddb81f4']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26bf.099a4ec3cc000b12"

   strings:
      $hex_string = { 00312e2db7a49b97ffa59b98fea69c99ff736c6aff847c7affa39996fe232425c106435b7f096488eb09688cfe096d90ff097194ff097699ff087a9cfe087ea0 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
