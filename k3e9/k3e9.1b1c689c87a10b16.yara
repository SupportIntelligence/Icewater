
rule k3e9_1b1c689c87a10b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.1b1c689c87a10b16"
     cluster="k3e9.1b1c689c87a10b16"
     cluster_size="2559"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="neshta nestha hllp"
     md5_hashes="['000fe19e51a8ae98c606af27fd5a4394','00284777f159458fd704a266764ea9f5','01f52c4fc57849b1cb44684904dc4f1d']"

   strings:
      $hex_string = { 08184edb8281f5a5d032aacb902b5efe90c7bae35797cb0b90b5e1d96eca1258fdb1152e9a74db4ef3c49e7493eee268ee11848bc06088b2f254f835fd9c9140 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
