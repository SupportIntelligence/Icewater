
rule k3e9_2914ad6994bb0b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.2914ad6994bb0b12"
     cluster="k3e9.2914ad6994bb0b12"
     cluster_size="22"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="tinba zusy emotet"
     md5_hashes="['008d5869f759dcd3ffbb86468905a416','025dd205a664e2fa7ac6f5055f4abbd6','c6979e319415cacb8523d111dd4673d0']"

   strings:
      $hex_string = { 1ec9cd8de4ce8864e786b32687b05203d9495a6eb846acd72a95729980bcbdeecbf06beff37d2683c366898402b54211a05107aa157aa534482d0e578ba2d4c2 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
