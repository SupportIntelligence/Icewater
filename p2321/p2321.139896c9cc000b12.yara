
rule p2321_139896c9cc000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=p2321.139896c9cc000b12"
     cluster="p2321.139896c9cc000b12"
     cluster_size="12"
     filetype = "PE32 executable (GUI) Intel 80386 (stripped to external PDB)"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family=""
     md5_hashes="['056e6b76feeef0c2d960863b11088b89','3397ee5f0312e30fb1d85aa6d7c569e0','f992f7c390928af52057306b3a127aad']"

   strings:
      $hex_string = { 09fa054d2271d1b1189b77f6259079c8631ac43ef0aa6901ddc616d05fdf0cc1b7fe3788f1da6852080affa044e49742e96557fb489c031b47d84b7eeff73193 }

   condition:
      
      filesize > 4194304 and filesize < 16777216
      and $hex_string
}
