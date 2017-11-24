
rule o3e9_29231304db5bb916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.29231304db5bb916"
     cluster="o3e9.29231304db5bb916"
     cluster_size="930"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="installmonster installmonstr malicious"
     md5_hashes="['001d5f54d9675dc82ca96e99f3cace99','008cb6c962e6cd1fe9b10cc4c109ce57','04d8caabecfd2fd392ba94d35c8c3e5b']"

   strings:
      $hex_string = { 60a3582146d14a1029c92d9f3302a9fad4be92ea0739171c68af490674ac2eeff3dc7f38205f6dfda0fb6b75edeccea53aaed3f5dee3b92863846a3d7a3b80a2 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
