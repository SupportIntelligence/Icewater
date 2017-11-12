
rule n3e9_1ba3200040000132
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.1ba3200040000132"
     cluster="n3e9.1ba3200040000132"
     cluster_size="924"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="allaple rahack jadtre"
     md5_hashes="['0170b5f9e1a74ba4cd0778284d55911f','017b20986fbd6b2b0bb14f14ffcad8ba','09d5ade2b23128b08a3340b5dae68041']"

   strings:
      $hex_string = { 0f8c000c83a27e2cec3663df144b0df4d0a7ba4cc087b73275fe4f29a15f88fa71fc02e09c2fd1446f68b6bdef45ad82671a7fe52e1cd8621965ce20c8bc21c3 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
