
rule m3e9_45464c5c132d2f14
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.45464c5c132d2f14"
     cluster="m3e9.45464c5c132d2f14"
     cluster_size="36"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus barys malicious"
     md5_hashes="['10e9df9ec2e0ccdda75d484679995519','1238eb50bfb8bb2c8a99dda884edc173','bee8bdc3e39d82c72151d0d80d9d5185']"

   strings:
      $hex_string = { 877cd6a89ff3b6b2f1bdc2efbcc2f3bdbffbc0bef2b5b7f59390dc7b71b8c4c1e8aad8ea6ce7ee2fe0f80ccafc0bbafd18adf41ca3f13092e15990cb86a3bea4 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
