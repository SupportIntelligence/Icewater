import "hash"

rule j3ec_4ac6d0999e934b92
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3ec.4ac6d0999e934b92"
     cluster="j3ec.4ac6d0999e934b92"
     cluster_size="547"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171105"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut crytex lxkr"
     md5_hashes="['00625d23e394c5c6608998a87bdfb69b','0065d494ebb7126be5c386d00ff0d8c0','07a2fffd75c9f0efc3aad6e4fe4f219f']"


   condition:
      
      filesize > 16384 and filesize < 65536
      and hash.md5(4096,4096) == "3c2979ef23b8a998d6bb250512dab5d1"
}

