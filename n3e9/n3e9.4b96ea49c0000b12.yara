import "hash"

rule n3e9_4b96ea49c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.4 divinorum/0.992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.4b96ea49c0000b12"
     cluster="n3e9.4b96ea49c0000b12"
     cluster_size="107 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171018"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="acrkm advml ceeinject"
     md5_hashes="['cdf709d7578b032f2d5f830189b28345', 'ba4364c797bae850a7e68559ed7d4d96', '64fefb91ccac9c7023817a6bde5ab49b']"


   condition:
      uint16(0) == 0x5A4D and 
      filesize > 262144 and filesize < 1048576
      and hash.md5(27648,1024) == "fb2c6e74a20f6c3f6c3d6d8b4b1542e9"
}

