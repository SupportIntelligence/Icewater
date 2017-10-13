import "hash"

rule o3ed_635244cece4bcb12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3ed.635244cece4bcb12"
     cluster="o3ed.635244cece4bcb12"
     cluster_size="64 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="ramnit nimnul bqjjnb"
     md5_hashes="['b6d7007229117794e0e44043cd5a7266', 'cbfdd153e0b53586893067bcdc518c65', 'b83ccaabb9d85eb118b00d36125bc95b']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(2711552,1024) == "b76cb8f54dcda147685e3a189523f6b0"
}

