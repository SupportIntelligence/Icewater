
rule n3e9_2585ea48c4000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.2585ea48c4000b32"
     cluster="n3e9.2585ea48c4000b32"
     cluster_size="372"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="otwycal wapomi viking"
     md5_hashes="['02aa8dfc87ac80b1947cb90cbdb9f732','0bacba46b53dd635b5780fb9a606e72d','2344c78585db3e59d7b6b912d346afb3']"

   strings:
      $hex_string = { e2f5e089f482945e05ec63ee59a3f1a083e4340b4ad0905946aac3564de1b314bfd909ce6d5540cc5a635fc24bd8123aace3615b3bed248c192edc71b0319c60 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
