
rule m3e9_611c5ae9c8800b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.611c5ae9c8800b32"
     cluster="m3e9.611c5ae9c8800b32"
     cluster_size="11"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob virux"
     md5_hashes="['0c84111e53d767e0319f28962ee03717','1bfb4010ee77cf5f929f2a06e16d2939','fe8782597fdd510835400a9d65cd9959']"

   strings:
      $hex_string = { 3bf37d10391da8e60001740b5668f0290001ebbe33db435e8d45f850ff15f41100015f8bc35bc9c20800558bec83ec1853568b750c5733db33c066895df08d7d }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
