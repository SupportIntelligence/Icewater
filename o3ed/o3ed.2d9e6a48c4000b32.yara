import "hash"

rule o3ed_2d9e6a48c4000b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3ed.2d9e6a48c4000b32"
     cluster="o3ed.2d9e6a48c4000b32"
     cluster_size="69 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="ramnit nimnul bqjjnb"
     md5_hashes="['e978c46c7d44a6b237cdd6aa4580fafa', 'bfde74678c2eefe33e4301472b1d41b4', 'cfd64f7254f5990025746ddb8792ad1f']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(942080,1024) == "f3160b267df10931da3e14c4717eba2c"
}

