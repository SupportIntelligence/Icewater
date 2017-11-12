
rule n3e9_13a1200040000132
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.13a1200040000132"
     cluster="n3e9.13a1200040000132"
     cluster_size="2475"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="allaple rahack jadtre"
     md5_hashes="['00166337762a79fa7a55c81786254abf','006567961f9192ddb6a5469e0d4cfdf4','03a30cd899ad046633eab2531e8c80eb']"

   strings:
      $hex_string = { 0f8c000c83a27e2cec3663df144b0df4d0a7ba4cc087b73275fe4f29a15f88fa71fc02e09c2fd1446f68b6bdef45ad82671a7fe52e1cd8621965ce20c8bc21c3 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
