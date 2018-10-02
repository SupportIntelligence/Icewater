
rule n3f8_483695ce6a008b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f8.483695ce6a008b12"
     cluster="n3f8.483695ce6a008b12"
     cluster_size="279"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="sandr androidos kasandra"
     md5_hashes="['e9e8a8a08b506abe51e3e73123fae0d6ae169031','6d362e0f0d0f9050ee2ca076cf3b053811121511','8ab29967aef6a9aa65229c6ec052de387ad50499']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n3f8.483695ce6a008b12"

   strings:
      $hex_string = { e30307000a04b1431504b4426e20900048006e10e60307000a047b4482445275a7011506803fc6657f558226c8656e3094004805547485016e30f30834025472 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
