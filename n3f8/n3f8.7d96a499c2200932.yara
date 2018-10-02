
rule n3f8_7d96a499c2200932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f8.7d96a499c2200932"
     cluster="n3f8.7d96a499c2200932"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="fakeinst androidos decrypter"
     md5_hashes="['7a83d89f029585cb60f7694eb9200647ff8c7e6b','66a59a28ba4a53452e100ea21c10a9a866d64ef0','44f34c86c505c0f518d8848051f89fd1547ac7a1']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n3f8.7d96a499c2200932"

   strings:
      $hex_string = { 2100002a025500d61c00002b0264076a0f00002c026007c11d00002d02c8060a2200002e026407580300002e028b074939000030023202313e0000330234026d }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
