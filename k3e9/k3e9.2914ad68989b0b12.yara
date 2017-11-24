
rule k3e9_2914ad68989b0b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.2914ad68989b0b12"
     cluster="k3e9.2914ad68989b0b12"
     cluster_size="4"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="tinba emotet vbkrypt"
     md5_hashes="['7360ab92061446e6841e584370cea6ee','980d50d98930c9396be17b975610c9fc','be455bf8baae1533d461bc23d94abd93']"

   strings:
      $hex_string = { 52386f103d393b06b2770ce0ece8cfde3580f5463fe6963eecf989bca9d1e2d4486d7c7890d1a057c865221e97c761b65faff3b8702c9d561b6a088837aa930d }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
