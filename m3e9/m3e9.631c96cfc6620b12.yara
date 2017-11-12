
rule m3e9_631c96cfc6620b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.631c96cfc6620b12"
     cluster="m3e9.631c96cfc6620b12"
     cluster_size="11112"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="allaple virut rahack"
     md5_hashes="['002ba19eae7b0346a845aac1809fba84','003101d6aac2f3d5104ba1a5a8fdc6b5','023982e57d24b61c94ffee750673d48b']"

   strings:
      $hex_string = { 0f8c000c83a27e2cec3663df144b0df4d0a7ba4cc087b73275fe4f29a15f88fa71fc02e09c2fd1446f68b6bdef45ad82671a7fe52e1cd8621965ce20c8bc21c3 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
