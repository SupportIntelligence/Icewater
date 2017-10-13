import "hash"

rule o3ed_131a9d99cea30916
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3ed.131a9d99cea30916"
     cluster="o3ed.131a9d99cea30916"
     cluster_size="343 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="ramnit nimnul bmnup"
     md5_hashes="['b4f136fa6c9c791797d63d7bfd6348e9', '176ace2ef0dedbbd20fff31f75b71740', 'a3ae2e82ef38dd4f12b546b749f4ef6d']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(2183168,1024) == "0e6e52e26906a323049b5f94126f2295"
}

