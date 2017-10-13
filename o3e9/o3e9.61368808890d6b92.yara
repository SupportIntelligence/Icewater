import "hash"

rule o3e9_61368808890d6b92
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.61368808890d6b92"
     cluster="o3e9.61368808890d6b92"
     cluster_size="5966 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="optimizerpro generickd speedingupmypc"
     md5_hashes="['00f0f56e5d027e476b40662794da315e', '05503d2195f4310e1d1e9f04760e26d1', '09a19c5d72e2204b1db5321abec76a85']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(3633664,1024) == "ad9f1a38ddffc6e3915831ed25ef4b27"
}

