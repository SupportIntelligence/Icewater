
rule mfc8_090eb509ad146b96
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=mfc8.090eb509ad146b96"
     cluster="mfc8.090eb509ad146b96"
     cluster_size="19"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="fakeinst androidos fakeins"
     md5_hashes="['7f31fd3f1ace80411e3a16d984c4c6a8df584154','cdc4a0e1773f42fe074520de072380650a9c6eb3','23df905fad14200042465eee96dd1915f68567f2']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=mfc8.090eb509ad146b96"

   strings:
      $hex_string = { ea15caeed537ac3f7a95f7c9ecdae0cd5dbb8e5c3c71edf655789ca06b8c4af03f02b406e1bc216e1d125753e4a94f172b7c6f2babe2aea1e5cf825a84300f0e }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
