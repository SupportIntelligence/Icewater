
rule n26bb_539e93d9cc000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bb.539e93d9cc000b32"
     cluster="n26bb.539e93d9cc000b32"
     cluster_size="11"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="bybji explorerhijack patched"
     md5_hashes="['49aa683cdecd9a530de648ac7e521762f31da899','431149ccf1ee65635800ec2f992875aea4f7e1f5','9a57c09e10b3c4ae43968487eb901af1ac721b05']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bb.539e93d9cc000b32"

   strings:
      $hex_string = { 01c351b8d34d6210f7e1535556578bfac1ef068bc769c0e80300002bc8740383c7018b2dcc50400032db885c241333f68bff807c241300752c3bf77328e830fd }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
