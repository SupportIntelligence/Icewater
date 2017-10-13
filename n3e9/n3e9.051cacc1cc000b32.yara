import "hash"

rule n3e9_051cacc1cc000b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.051cacc1cc000b32"
     cluster="n3e9.051cacc1cc000b32"
     cluster_size="176 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="allaple rahack networm"
     md5_hashes="['a395a03ef65b66fa5f0721c9c21ec908', 'd5646ebc99f4f37811d07219672d9b98', 'a460bb19e0b629b360d8a9bb7c327c01']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(83456,1024) == "4a4080ab9387ebb9aea646c2e4b067fe"
}

