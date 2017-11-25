
rule m3e9_13e99ac1c8001116
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.13e99ac1c8001116"
     cluster="m3e9.13e99ac1c8001116"
     cluster_size="55"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="installcore unwanted click"
     md5_hashes="['073efa69bb4240c0fa7c201aa4a8a00b','1592796d0001d79ce6b2fc1c44f28eb4','4cd204928c2fa33f8985d1f1a1b59d3a']"

   strings:
      $hex_string = { c04a611df12f0efabe79f7a523ef55519684cddbe3b96e3e31d80a2067c7f4d9bf94eb47043e02ce2aa25d870409f6309d188a97b2aa1cfc41d2a136cbfb3d91 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
