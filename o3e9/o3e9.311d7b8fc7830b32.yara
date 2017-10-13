import "hash"

rule o3e9_311d7b8fc7830b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.311d7b8fc7830b32"
     cluster="o3e9.311d7b8fc7830b32"
     cluster_size="977 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="backdoor genome hupigon"
     md5_hashes="['6299e59e86b4e7058a7a2ddeb0ce03fa', '4c3282cfc9f7f347a4bf05a5619cafcf', '5481fb67e5193426d8d8b23b6ad2d930']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(188416,1024) == "a848a2906093ba9ffa0c6edc2efb74e5"
}

