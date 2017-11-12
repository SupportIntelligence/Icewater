
rule n3e9_1697159dc6620b54
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.1697159dc6620b54"
     cluster="n3e9.1697159dc6620b54"
     cluster_size="700"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut allaple virtob"
     md5_hashes="['016546979d61aa1a760febbff49589a9','01fb06a40704edd100e80846e0b04410','06e9fcf1108dc92fa3e2977be64fba0e']"

   strings:
      $hex_string = { 0f8c000c83a27e2cec3663df144b0df4d0a7ba4cc087b73275fe4f29a15f88fa71fc02e09c2fd1446f68b6bdef45ad82671a7fe52e1cd8621965ce20c8bc21c3 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
