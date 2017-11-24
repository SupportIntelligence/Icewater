
rule k3e9_13ac3695c1bce133
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.13ac3695c1bce133"
     cluster="k3e9.13ac3695c1bce133"
     cluster_size="4"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="peed backdoor qukart"
     md5_hashes="['506c5060a06e2d692274f62d98c6c7a0','a005661ccc9dff8061040ff37f0e8117','d7f6918fc9674c739ae0af99be54c341']"

   strings:
      $hex_string = { 636573734100000000930257616974466f7253696e676c654f626a65637400000097025769646543686172546f4d756c746942797465000000980257696e4578 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
