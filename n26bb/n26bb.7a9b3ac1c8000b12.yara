
rule n26bb_7a9b3ac1c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bb.7a9b3ac1c8000b12"
     cluster="n26bb.7a9b3ac1c8000b12"
     cluster_size="55"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="bunitu kryptik trojanproxy"
     md5_hashes="['7fb18238a25b8cdccf26dbe81090136bac5c51d7','e6fd56d56f9db0a87504956774b8232256e4e595','8004e840feb417a2de9025921e7ee14aeb821903']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bb.7a9b3ac1c8000b12"

   strings:
      $hex_string = { b792b09200b6fe09b98635ce33fa30ae33e6fd1001c6b1a2baa2b63737ba323638ca00a90412bc36b84eb45a2f82b2a40512016ab3d23a42a7a2337e2696a306 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
