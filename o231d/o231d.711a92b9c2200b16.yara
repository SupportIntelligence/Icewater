
rule o231d_711a92b9c2200b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o231d.711a92b9c2200b16"
     cluster="o231d.711a92b9c2200b16"
     cluster_size="6"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="fakeapp riskware clicker"
     md5_hashes="['c532f19c716a97d041e0f697e46af42d54abd890','139e91633b00486935bae025ac33a6adc98e6888','08f9e773f9acd2efc5259800d21491018579d0d8']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o231d.711a92b9c2200b16"

   strings:
      $hex_string = { a97933d2f31c63e8808d9e3d87652e45408bfd462652030412a620544a16ea245e97e9a809b8e7a57699b353cc5dab35f1e122fe9b0fcef9693b4fafd155c1c0 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
