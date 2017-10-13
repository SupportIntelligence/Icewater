import "hash"

rule n3e9_151aacc1cc000b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.151aacc1cc000b32"
     cluster="n3e9.151aacc1cc000b32"
     cluster_size="278 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="allaple rahack networm"
     md5_hashes="['c4178a926f2f0e82f30dcce625146250', 'a299cb9ffb3ff41a4304daa8406e59cf', 'a299cb9ffb3ff41a4304daa8406e59cf']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(83456,1024) == "4a4080ab9387ebb9aea646c2e4b067fe"
}

