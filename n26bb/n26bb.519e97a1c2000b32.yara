
rule n26bb_519e97a1c2000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bb.519e97a1c2000b32"
     cluster="n26bb.519e97a1c2000b32"
     cluster_size="19"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="explorerhijack patched malicious"
     md5_hashes="['7fe75c12574cd865720072b79de531b07b6417c1','0ac48c185a2f34c3e8c40605baa63ac65bc8be33','f2f331a6856b59c0cd81ab2b8cc13a0a2234ee33']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bb.519e97a1c2000b32"

   strings:
      $hex_string = { 01c351b8d34d6210f7e1535556578bfac1ef068bc769c0e80300002bc8740383c7018b2dcc50400032db885c241333f68bff807c241300752c3bf77328e830fd }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
