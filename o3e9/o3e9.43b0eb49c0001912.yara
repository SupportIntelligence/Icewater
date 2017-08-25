import "hash"

rule o3e9_43b0eb49c0001912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.43b0eb49c0001912"
     cluster="o3e9.43b0eb49c0001912"
     cluster_size="15493 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170816"
     license = "non-commercial use only"
     family="nimnul vjadtre wapomi"
     md5_hashes="['035bae844d5944a98c9a4d9ed47820c8', '012b12b9d0effb9d07ec10e0edd8605a', '049e9eabf671b57351c6097d5e46db7a']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(823296,1024) == "87eb1721305da946a1b87ff9207f629a"
}

