import "hash"

rule o3ed_131a9d99d6830916
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3ed.131a9d99d6830916"
     cluster="o3ed.131a9d99d6830916"
     cluster_size="119 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="ramnit nimnul bmnup"
     md5_hashes="['c3cff434bdf5a0b6fde2d27780db6055', 'b641668bbbc6eca777a0fd3ce12c9fd0', '5ec17716db26f712423dd156b9a6910d']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(2137088,1024) == "ff5f1f7c34de76a2ed3703a11514ea4f"
}

