
rule m3f8_5b4fa12c6446e6e3
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f8.5b4fa12c6446e6e3"
     cluster="m3f8.5b4fa12c6446e6e3"
     cluster_size="29"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="banker androidos asacub"
     md5_hashes="['8b91c8337cb8d4fad69cd428bfc54ffad17d7869','aa2326cc7cb88d7d6be474883d36ae882f187755','9aab6b9588dafe96085897b4f2b45deb5077b6ea']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m3f8.5b4fa12c6446e6e3"

   strings:
      $hex_string = { 106e0104000a016e10640104000c0072301a0850060a003800f3ff54422f007210fa0702000a0254433300b1127120820123003901e5ff6e106201040028e003 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
