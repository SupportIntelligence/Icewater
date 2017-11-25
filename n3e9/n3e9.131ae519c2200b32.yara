
rule n3e9_131ae519c2200b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.131ae519c2200b32"
     cluster="n3e9.131ae519c2200b32"
     cluster_size="232"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="allaple virut rahack"
     md5_hashes="['016e667cd240e4c530339ac6189554b8','029c3cb81dd0c90005596cdae718b9de','212e113218ed9961d7fc78e42b72de93']"

   strings:
      $hex_string = { 367cbf084d78f1b49149600b48fa8341fe510c742d436361d06632219a4f5a208b5baf90c875e3c959a7e6c07177e7675eda68b7bb64dff094318feee5b5ff09 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
