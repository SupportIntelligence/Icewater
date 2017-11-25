
rule m3e9_6114c0a4b13b0912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.6114c0a4b13b0912"
     cluster="m3e9.6114c0a4b13b0912"
     cluster_size="7"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="allaple rahack virut"
     md5_hashes="['3f47406e0e26ee4dd87ac244b67644be','cdd6ae21966bac66f1d6f2497cc0f04d','f1db700aa518d268ef5dd9d9a3d25cf0']"

   strings:
      $hex_string = { 16fef1923b5511353aec0dda8477dcfaca1836874ba2a1cf5eba6d23a34197e56c8a6e2520768c138e1f7b5848a779c4bd0bf627d746b3f817519603f4c549eb }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
