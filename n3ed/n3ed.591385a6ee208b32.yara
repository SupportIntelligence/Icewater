import "hash"

rule n3ed_591385a6ee208b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.591385a6ee208b32"
     cluster="n3ed.591385a6ee208b32"
     cluster_size="364 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="ramnit nimnul bmnup"
     md5_hashes="['079fe5a7e9f0b8be9472894092fc4c1a', 'c56b0f8bbb67604e8eb26a484646d592', 'b00ffe8e54074cb65f79dcd59e2b93d3']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(423936,1076) == "2464ede2d3405b3c500e9c2c3d78ec04"
}

