
rule o231d_711c90b9caa00b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o231d.711c90b9caa00b12"
     cluster="o231d.711c90b9caa00b12"
     cluster_size="12"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="fakeapp riskware androidos"
     md5_hashes="['85ebe4eba8da54449ec88ce05fba586937cb7e12','6e00284b70cda77f9fe6abfbec764673f2fda025','b3d78458ffb3e0a5bae414ba68ee6e38bebd0737']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o231d.711c90b9caa00b12"

   strings:
      $hex_string = { a97933d2f31c63e8808d9e3d87652e45408bfd462652030412a620544a16ea245e97e9a809b8e7a57699b353cc5dab35f1e122fe9b0fcef9693b4fafd155c1c0 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
